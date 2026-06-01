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
    call_appsec_api,
    format_findings,
    parse_findings,
)
from suppression import apply_suppressions, find_git_root, load_armisignore  # noqa: E402


def main() -> None:
    try:
        init_auth(APPSEC_API_URL)
    except RuntimeError as e:
        print(f"appsec: auth failed — {e}", file=sys.stderr)
        sys.exit(0)  # fail-open

    result = subprocess.run(
        ["git", "diff", "--cached", "--no-color", "--no-ext-diff"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if not result.stdout.strip():
        print("appsec: no staged changes to scan", file=sys.stderr)
        sys.exit(0)

    response = call_appsec_api(result.stdout)
    findings = parse_findings(response)

    git_root = find_git_root()
    config = load_armisignore(git_root)
    active, _suppressed, _summary = apply_suppressions(findings, config)

    # Suppressed HIGH does not block (team already accepted risk via .armisignore).
    # Suppressed CRITICAL still blocks (requires explicit approve_findings).
    suppressed_critical = [f for f in _suppressed if f.get("severity") == "CRITICAL"]
    blocking = [f for f in active if f.get("severity") in ("HIGH", "CRITICAL")]
    blocking.extend(suppressed_critical)

    if blocking:
        print(format_findings(blocking, filename="staged-diff"), file=sys.stderr)
        print(
            f"\nappsec: {len(blocking)} HIGH/CRITICAL findings. Fix before committing.",
            file=sys.stderr,
        )
        sys.exit(1)

    staged_hash = hashlib.sha256(result.stdout.encode()).hexdigest()
    cleanup_legacy_scan_pass()  # remove any stale working-tree .scan-pass
    scan_pass_path = resolve_scan_pass_path()
    tmp_path_file = scan_pass_path + ".tmp"
    with open(tmp_path_file, "w") as f:
        f.write(staged_hash)
    os.replace(tmp_path_file, scan_pass_path)
    print("appsec: scan clean. scan-pass written.", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"appsec: scan failed — {e} (commit allowed)", file=sys.stderr)
        sys.exit(0)  # fail-open
