#!/usr/bin/env python3
"""Scan a file for security vulnerabilities using the Armis AppSec scanner.

Usage: python3 scan_file.py <file_path>

This script calls the same scanning engine as the MCP server but can be
invoked directly from editors that cannot call MCP tools natively.
Exit codes: 0 = clean or no findings, 1 = findings found, 2 = usage error.
"""

import os
import sys

_plugin_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _plugin_dir)

from dotenv import load_dotenv  # noqa: E402

_env_file = os.path.join(_plugin_dir, ".env")
if os.path.isfile(_env_file):
    load_dotenv(_env_file, override=False)

from auth import init_auth  # noqa: E402
from scanner_core import (  # noqa: E402
    APPSEC_API_URL,
    call_appsec_api,
    format_findings,
    parse_findings,
)


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python3 scan_file.py <file_path>", file=sys.stderr)
        sys.exit(2)

    file_path = os.path.abspath(sys.argv[1])
    if not os.path.isfile(file_path):
        print(f"Error: {file_path} not found", file=sys.stderr)
        sys.exit(2)

    init_auth(APPSEC_API_URL)

    with open(file_path) as f:
        code = f.read()

    raw = call_appsec_api(code)
    findings = parse_findings(raw)

    if findings:
        print(format_findings(findings, os.path.basename(file_path)))
        sys.exit(1)
    else:
        print(f"No findings in {os.path.basename(file_path)}")
        sys.exit(0)


if __name__ == "__main__":
    main()
