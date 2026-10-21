#!/usr/bin/env python3
"""Standalone pre-commit scan -- calls the scanner directly, no MCP client needed.

Run via the plugin venv:
    .venv/bin/python git-hooks/scan-staged.py
"""

import os
import subprocess
import sys

_plugin_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _plugin_dir)

from dotenv import load_dotenv  # noqa: E402

load_dotenv(os.path.join(_plugin_dir, ".env"))

from auth import init_auth  # noqa: E402
from hash_utils import compute_staged_hash  # noqa: E402
from net_config import configure_ca_trust, configure_proxy  # noqa: E402
from scan_gate import (  # noqa: E402
    DIFF_CONTEXT_LINES,
    DIFF_FILTER_ARGS,
    MAX_CODE_CHARS,
    blocks_scan_pass,
    clip_diff,
    shipping_decision,
    write_or_clear_scan_pass,
)
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

# Mirrors server.scan_diff(staged=True): same shipping rules via scan_gate, so a
# diff the MCP tool refuses to vouch for cannot earn a pass through this hook.


def main() -> None:
    # Same OS CA store / system proxy handling as the MCP server (net_config).
    configure_ca_trust()
    configure_proxy(APPSEC_API_URL)
    try:
        init_auth(APPSEC_API_URL)
    except RuntimeError as e:
        print(f"appsec: auth failed — {e}", file=sys.stderr)
        sys.exit(0)  # fail-open

    # The diff the scanner sees is the same one scan_diff builds (deleted files
    # excluded, same context). The pass hash is NOT taken from it: the gate
    # reader hashes the full `git diff --cached`, so use compute_staged_hash().
    # errors="replace" keeps non-UTF-8 staged content from raising
    # UnicodeDecodeError -> the fail-open catch-all, which would silently allow
    # an unscanned commit.
    result = subprocess.run(
        ["git", "diff", "--cached", *DIFF_FILTER_ARGS, f"-U{DIFF_CONTEXT_LINES}", "--"],
        capture_output=True,
        timeout=10,
    )
    if result.returncode != 0:
        # Surfaces as "scan failed — … (commit allowed)" via the fail-open catch-all,
        # instead of mistaking a failed `git diff` for "nothing staged".
        raise RuntimeError(f"git diff failed: {result.stderr.decode('utf-8', 'replace').strip()}")
    diff_text = result.stdout.decode("utf-8", errors="replace").strip()
    if not diff_text:
        # Nothing staged, or only deletions: scan_diff writes no pass here either.
        print("appsec: no staged changes to scan", file=sys.stderr)
        sys.exit(0)

    diff_text, truncated = clip_diff(diff_text)
    is_shipping_scan, require_approval = shipping_decision("", True, truncated, None)
    if truncated:
        print(
            f"appsec: WARNING: staged diff exceeded {MAX_CODE_CHARS} chars and was truncated; "
            "only the first part is scanned. This scan CANNOT authorize a commit "
            "(no scan-pass written). Split your changes into smaller commits and re-scan each.",
            file=sys.stderr,
        )
    scan_hash = compute_staged_hash() if is_shipping_scan else ""

    # Drop .armisignore-excluded paths before the API call (saves cost, matches
    # scan_diff). If nothing is left there is nothing to find: clean scan.
    git_root = find_git_root()
    config = load_armisignore(git_root)
    if git_root and config.file_patterns:
        diff_text = filter_diff_excluded_paths(diff_text, config, git_root)

    if diff_text.strip():
        response = call_appsec_api(diff_text)
        findings = parse_findings(response)
        active, suppressed, _summary = apply_suppressions(findings, config)

        # Inline armis:ignore against the staged diff blob (same string the API scanned).
        line_map, _changed = build_diff_line_map(diff_text)
        active, inline_suppressed = apply_inline_suppressions_to_diff(active, diff_text, line_map)
        suppressed = suppressed + inline_suppressed
    else:
        print("appsec: all staged files excluded by .armisignore", file=sys.stderr)
        active, suppressed = [], []

    # The gate rules (active HIGH/CRITICAL or any suppressed CRITICAL blocks;
    # suppressed HIGH does not; a stale pass is removed on a block) live in
    # scan_gate, shared with server.scan_diff.
    blocking = blocks_scan_pass(active, suppressed)
    if is_shipping_scan:
        write_or_clear_scan_pass(
            active,
            suppressed,
            scan_hash=scan_hash,
            repo_path=None,
            require_approval=require_approval,
        )

    if blocking:
        shown = [f for f in active if (f.get("severity") or "").upper() in ("HIGH", "CRITICAL")]
        shown.extend(f for f in suppressed if (f.get("severity") or "").upper() == "CRITICAL")
        print(format_findings(shown, filename="staged-diff"), file=sys.stderr)
        print(
            f"\nappsec: {len(shown)} HIGH/CRITICAL findings. Fix before committing.",
            file=sys.stderr,
        )
        sys.exit(1)

    if truncated:
        sys.exit(0)  # scanned clean, but no pass: see the warning above
    print("appsec: scan clean. scan-pass written.", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"appsec: scan failed — {e} (commit allowed)", file=sys.stderr)
        sys.exit(0)  # fail-open
