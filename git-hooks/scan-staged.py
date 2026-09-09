#!/usr/bin/env python3
"""Standalone pre-commit scan -- calls the scanner directly, no MCP client needed.

Run via the plugin venv:
    .venv/bin/python git-hooks/scan-staged.py
"""

import hashlib
import os
import subprocess
import sys

_plugin_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _plugin_dir)

from dotenv import load_dotenv  # noqa: E402

load_dotenv(os.path.join(_plugin_dir, ".env"))

from auth import init_auth  # noqa: E402
from hash_utils import cleanup_legacy_scan_pass, resolve_scan_pass_path  # noqa: E402
from scanner_core import (  # noqa: E402
    APPSEC_API_URL,
    build_diff_line_map,
    call_appsec_api,
    format_findings,
    parse_findings,
)
from suppression import (  # noqa: E402
    apply_inline_suppressions_to_diff,
    apply_suppressions,
    filter_diff_excluded_paths,
    find_git_root,
    load_armisignore,
)


def _write_scan_pass(raw_diff: bytes) -> None:
    """Record a passing scan for git-hooks/pre-commit to verify.

    Hashes the *unfiltered* staged diff, which is what hash_utils.compute_staged_hash
    and git-hooks/pre-commit hash. Any filtering applied to the text sent to the API
    must not reach this hash, or the gate reader can never match it.
    """
    staged_hash = hashlib.sha256(raw_diff).hexdigest()
    cleanup_legacy_scan_pass()  # remove any stale working-tree .scan-pass
    scan_pass_path = resolve_scan_pass_path()
    tmp_path_file = scan_pass_path + ".tmp"
    with open(tmp_path_file, "w") as f:
        f.write(staged_hash)
    os.replace(tmp_path_file, scan_pass_path)


def main() -> None:
    try:
        init_auth(APPSEC_API_URL)
    except RuntimeError as e:
        print(f"appsec: auth failed — {e}", file=sys.stderr)
        sys.exit(0)  # fail-open

    result = subprocess.run(
        ["git", "diff", "--cached", "--no-color", "--no-ext-diff"],
        capture_output=True,
        timeout=10,
    )
    if not result.stdout.strip():
        print("appsec: no staged changes to scan", file=sys.stderr)
        sys.exit(0)

    # Hash the raw bytes (matches hash_utils.compute_staged_hash so the gate
    # reader agrees), but decode a text copy for the API. errors="replace"
    # keeps non-UTF-8 staged content from raising UnicodeDecodeError → the
    # fail-open catch-all, which would silently allow an unscanned commit.
    diff_text = result.stdout.decode("utf-8", errors="replace")

    git_root = find_git_root()
    config = load_armisignore(git_root)

    # Drop diff sections for files excluded by .armisignore path patterns before
    # the API call, exactly as server.py's scan_diff does. Without this the path
    # patterns are a silent no-op in the git hook: apply_suppressions() below only
    # matches a finding's cwe/severity/category, never its file, so an excluded
    # file was still scanned and could still block the commit. Filter only the text
    # sent to the API -- the scan-pass hash stays over the unfiltered diff.
    if git_root and config.file_patterns:
        diff_text = filter_diff_excluded_paths(diff_text, config, git_root)
        if not diff_text.strip():
            # Nothing left to scan is a clean scan, not an absent one: write the
            # scan-pass so a repo that legitimately excludes every staged file is
            # not blocked by git-hooks/pre-commit under APPSEC_HOOK_STRICT=1.
            _write_scan_pass(result.stdout)
            print(
                "appsec: all changed files excluded by .armisignore. scan-pass written.",
                file=sys.stderr,
            )
            sys.exit(0)

    response = call_appsec_api(diff_text)
    findings = parse_findings(response)

    active, _suppressed, _summary = apply_suppressions(findings, config)

    # Apply inline armis:ignore suppression against the staged diff blob. Keeps the
    # git hook interchangeable with the MCP scan_diff flow (same scan-pass behavior).
    # Use the decoded text copy (same string the API scanned) for line mapping and
    # inline suppression -- the raw result.stdout is bytes here (hashed below to match
    # hash_utils.compute_staged_hash), but these helpers operate on str.
    line_map, _changed = build_diff_line_map(diff_text)
    active, inline_suppressed = apply_inline_suppressions_to_diff(active, diff_text, line_map)

    # Suppressed HIGH does not block (team already accepted risk via .armisignore /
    # an inline directive). Suppressed CRITICAL still blocks (requires approve_findings).
    # Normalize severity case to match server.py (parse_findings does not normalize,
    # and the model may emit lowercase) -- keeps the gate identical across both flows.
    def _sev(finding: dict) -> str:
        return (finding.get("severity") or "").upper()

    suppressed_critical = [f for f in _suppressed if _sev(f) == "CRITICAL"]
    inline_suppressed_critical = [f for f in inline_suppressed if _sev(f) == "CRITICAL"]
    blocking = [f for f in active if _sev(f) in ("HIGH", "CRITICAL")]
    blocking.extend(suppressed_critical)
    blocking.extend(inline_suppressed_critical)

    if blocking:
        print(format_findings(blocking, filename="staged-diff"), file=sys.stderr)
        print(
            f"\nappsec: {len(blocking)} HIGH/CRITICAL findings. Fix before committing.",
            file=sys.stderr,
        )
        sys.exit(1)

    _write_scan_pass(result.stdout)
    print("appsec: scan clean. scan-pass written.", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"appsec: scan failed — {e} (commit allowed)", file=sys.stderr)
        sys.exit(0)  # fail-open
