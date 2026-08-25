#!/usr/bin/env python3
"""Armis AppSec scanner CLI -- the gating scanner, callable as an installed console script.

Three scan sources, so that the SAME hook definition works at every point of a
normal development workflow:

    armis-scan-staged                       # staged diff (git pre-commit)
    armis-scan-staged --ref origin/develop  # branch diff (CI, nothing staged)
    armis-scan-staged src/a.py src/b.py     # explicit files (`pre-commit run --all-files`)

Upstream `git-hooks/scan-staged.py` only ever scanned `git diff --cached`, which makes
it a no-op in CI (a fresh checkout has nothing staged -> "no staged changes" -> exit 0,
a green stage that scanned nothing). The file and ref modes exist to close that.

Suppression, path exclusion, truncation and the scan-pass token all behave the same
across modes, except that the scan-pass token is only written for a staged scan --
that token is a staged-hash claim and means nothing for the other two sources.

Warn-only mode (--warn-only) reports findings and still exits 0. A gate whose
false-positive rate is unmeasured cannot be turned on blocking without stalling every
team it lands on; warn-only lets a rollout collect that rate from real repositories
first, and is meant to be temporary.

Failure policy: fail-open by default (a scanner outage must not stop every commit in
the org), fail-closed with --strict or APPSEC_HOOK_STRICT=1. This is enforced here in
`cli_main` rather than under `if __name__ == "__main__":` so that a console-script
entry point gets the same policy as `python scan_staged_cli.py`.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys

from auth import init_auth
from hash_utils import cleanup_legacy_scan_pass, resolve_scan_pass_path
from scanner_core import (
    APPSEC_API_URL,
    build_diff_line_map,
    call_appsec_api,
    format_findings,
    parse_findings,
)
from suppression import (
    ArmisIgnoreConfig,
    apply_inline_suppressions_to_diff,
    apply_suppressions,
    filter_diff_excluded_paths,
    find_git_root,
    is_path_excluded,
    load_armisignore,
)

# Mirrors server.py's _MAX_CODE_CHARS. The upstream git-hook scanner had no limit at
# all, so an oversized diff reached the API unbounded and any resulting error was
# swallowed by the fail-open catch-all -- an unscanned commit reported as clean.
MAX_CODE_CHARS = 90_000

# Text extensions the fast-scan model can reason about. Used only in --files mode to
# skip binaries and data blobs; diff modes are already scoped by git.
_SCANNABLE_EXTS = {
    ".py",
    ".ipynb",
    ".sh",
    ".bash",
    ".zsh",
    ".rb",
    ".pl",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".groovy",
    ".go",
    ".rs",
    ".c",
    ".h",
    ".cpp",
    ".cc",
    ".cs",
    ".swift",
    ".php",
    ".dart",
    ".sql",
    ".tf",
    ".hcl",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".dockerfile",
    ".r",
}


def _strict_mode(args: argparse.Namespace) -> bool:
    """Fail-closed if --strict or APPSEC_HOOK_STRICT=1. Matches git-hooks/pre-commit."""
    if args.strict:
        return True
    return os.environ.get("APPSEC_HOOK_STRICT", "") == "1"


def _run_git_diff(extra: list[str]) -> bytes:
    cmd = ["git", "diff", "--no-color", "--no-ext-diff", "--diff-filter=d", *extra]
    result = subprocess.run(cmd, capture_output=True, timeout=30)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git diff failed: {stderr}")
    return result.stdout


def _synthesize_diff(paths: list[str], git_root: str | None) -> str:
    """Render whole files as an all-added unified diff.

    `pre-commit run --all-files` hands us filenames, not a diff, and the scan API takes
    one code blob. Emitting `+++ b/<path>` headers and `+` content lines means
    build_diff_line_map / apply_inline_suppressions_to_diff / format_findings keep
    working unchanged and findings stay attributed to a real file and line.
    """
    parts: list[str] = []
    for path in paths:
        try:
            with open(path, encoding="utf-8-sig") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError):
            continue  # unreadable or binary: nothing to scan
        if not content.strip():
            continue
        lines = content.splitlines()
        rel = os.path.relpath(path, git_root) if git_root else path
        rel = rel.replace(os.sep, "/")
        parts.append(
            f"diff --git a/{rel} b/{rel}\n"
            "new file mode 100644\n"
            "--- /dev/null\n"
            f"+++ b/{rel}\n"
            f"@@ -0,0 +1,{len(lines)} @@\n" + "".join(f"+{line}\n" for line in lines)
        )
    return "".join(parts)


def _select_files(paths: list[str], config: ArmisIgnoreConfig, git_root: str | None) -> list[str]:
    """Drop non-files, unscannable extensions, and .armisignore path exclusions."""
    selected = []
    for path in paths:
        if not os.path.isfile(path):
            continue
        ext = os.path.splitext(path)[1].lower()
        if ext not in _SCANNABLE_EXTS:
            continue
        if git_root and is_path_excluded(os.path.abspath(path), config, git_root):
            print(f"appsec: skipping {path} (.armisignore)", file=sys.stderr)
            continue
        selected.append(path)
    return selected


def _blocking_findings(
    diff_text: str, config: ArmisIgnoreConfig
) -> tuple[list[dict], int, dict[int, tuple[str, int]], list[str]]:
    """Scan one code blob.

    Returns (blocking findings, total findings, line_map, changed_files). The last two
    are what let format_findings() translate a finding's diff-blob line number into a
    real `path:line` -- upstream never passed them, so every git-hook finding was
    reported at a blob coordinate that looks like a file line and is not.
    """
    response = call_appsec_api(diff_text)
    findings = parse_findings(response)

    active, suppressed, _summary = apply_suppressions(findings, config)
    line_map, changed = build_diff_line_map(diff_text)
    active, inline_suppressed = apply_inline_suppressions_to_diff(active, diff_text, line_map)

    def _sev(finding: dict) -> str:
        return (finding.get("severity") or "").upper()

    # Suppressed HIGH does not block (risk accepted via .armisignore / inline directive).
    # Suppressed CRITICAL still blocks. Same gate as upstream and as server.py.
    blocking = [f for f in active if _sev(f) in ("HIGH", "CRITICAL")]
    blocking.extend(f for f in suppressed if _sev(f) == "CRITICAL")
    blocking.extend(f for f in inline_suppressed if _sev(f) == "CRITICAL")
    return blocking, len(findings), line_map, changed


def _write_scan_pass(raw_diff: bytes) -> None:
    """Record the staged-hash claim that git-hooks/pre-commit verifies."""
    staged_hash = hashlib.sha256(raw_diff).hexdigest()
    cleanup_legacy_scan_pass()
    scan_pass_path = resolve_scan_pass_path()
    tmp_path_file = scan_pass_path + ".tmp"
    with open(tmp_path_file, "w") as f:
        f.write(staged_hash)
    os.replace(tmp_path_file, scan_pass_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="armis-scan-staged",
        description="Scan code with the Armis AppSec API and block on HIGH/CRITICAL findings.",
    )
    parser.add_argument(
        "paths", nargs="*", help="Files to scan. Omit to scan a diff (see --ref/--staged)."
    )
    parser.add_argument("--ref", default=None, help="Scan `git diff <ref>` instead of the index.")
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Force staged-diff mode even when paths are passed (default when no paths).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail closed: exit non-zero on auth/scan errors instead of allowing the commit.",
    )
    parser.add_argument(
        "--warn-only",
        action="store_true",
        help="Report HIGH/CRITICAL findings but always exit 0. For piloting a new gate.",
    )
    parser.add_argument(
        "--no-scan-pass",
        action="store_true",
        help="Do not write the scan-pass token on a clean staged scan.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    strict = _strict_mode(args)

    try:
        init_auth(APPSEC_API_URL)
    except RuntimeError as e:
        print(f"appsec: auth failed — {e}", file=sys.stderr)
        return 1 if strict else 0

    git_root = find_git_root()
    config = load_armisignore(git_root)

    raw_diff = b""
    if args.paths and not args.staged and not args.ref:
        selected = _select_files(args.paths, config, git_root)
        if not selected:
            print("appsec: no scannable files after exclusions", file=sys.stderr)
            return 0
        diff_text = _synthesize_diff(selected, git_root)
        # format_findings() appends its own "(N file(s))" from changed_files, so the
        # blocking-report label must not repeat the count -- the clean line has no
        # such suffix, so it carries the count itself.
        label = "files"
        clean_label = f"{len(selected)} file(s)"
    else:
        raw_diff = _run_git_diff([args.ref] if args.ref else ["--cached"])
        if not raw_diff.strip():
            # Wording kept verbatim for the staged case: git-hooks/pre-commit and the
            # existing test suite both key off "no staged changes".
            if args.ref:
                print(f"appsec: no changes to scan ({args.ref})", file=sys.stderr)
            else:
                print("appsec: no staged changes to scan", file=sys.stderr)
            return 0
        diff_text = raw_diff.decode("utf-8", errors="replace")
        # Upstream never called this -- .armisignore path patterns were a silent no-op
        # in the git hook while working in the MCP scan_diff tool.
        if git_root and config.file_patterns:
            diff_text = filter_diff_excluded_paths(diff_text, config, git_root)
            if not diff_text.strip():
                print("appsec: all changed files excluded by .armisignore", file=sys.stderr)
                return 0
        label = clean_label = args.ref or "staged-diff"

    if not diff_text.strip():
        print("appsec: nothing to scan", file=sys.stderr)
        return 0

    if len(diff_text) > MAX_CODE_CHARS:
        print(
            f"appsec: input {len(diff_text)} chars exceeds {MAX_CODE_CHARS}; "
            "scanning the first part only",
            file=sys.stderr,
        )
        diff_text = diff_text[:MAX_CODE_CHARS]

    blocking, total, line_map, changed_files = _blocking_findings(diff_text, config)

    if blocking:
        print(
            format_findings(
                blocking, filename=label, line_map=line_map, changed_files=changed_files
            ),
            file=sys.stderr,
        )
        if args.warn_only:
            print(
                f"\nappsec: {len(blocking)} HIGH/CRITICAL findings (warn-only, not blocking).",
                file=sys.stderr,
            )
            return 0
        print(
            f"\nappsec: {len(blocking)} HIGH/CRITICAL findings. Fix before committing.",
            file=sys.stderr,
        )
        return 1

    if raw_diff and not args.ref and not args.no_scan_pass:
        _write_scan_pass(raw_diff)
        print(
            f"appsec: scan clean ({total} finding(s), none blocking). scan-pass written.",
            file=sys.stderr,
        )
    else:
        print(
            f"appsec: scan clean ({total} finding(s), none blocking) — {clean_label}",
            file=sys.stderr,
        )
    return 0


def cli_main() -> None:
    """Console-script entry point. Applies the fail policy to unexpected exceptions.

    Upstream put this catch-all under `if __name__ == "__main__":`, so installing the
    scanner as a console script silently converted fail-open into fail-closed-with-a-
    traceback. Keeping it in the entry point makes the policy explicit and identical
    for both invocation styles.
    """
    strict = os.environ.get("APPSEC_HOOK_STRICT", "") == "1" or "--strict" in sys.argv
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:
        verdict = "commit blocked" if strict else "commit allowed"
        print(f"appsec: scan failed — {e} ({verdict})", file=sys.stderr)
        sys.exit(1 if strict else 0)


if __name__ == "__main__":
    cli_main()
