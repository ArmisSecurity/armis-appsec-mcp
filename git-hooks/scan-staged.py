#!/usr/bin/env python3
"""Standalone pre-commit scan -- calls the scanner directly, no MCP client needed.

Run via the plugin venv:
    .venv/bin/python git-hooks/scan-staged.py

This is now a thin clone-mode shim over ``hooks.scan_staged_cli``, which is the single
implementation and is also exposed as the ``armis-scan-staged`` console script. The two
things this file adds are the two things only a clone has: the repo root on sys.path,
and ``<plugin_dir>/.env``. Installed venvs (including the one the ``pre-commit``
framework builds) have neither and use the console script instead.

Accepts the same arguments as ``armis-scan-staged`` (--ref, --strict, file paths).
"""

import os
import sys

_plugin_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _plugin_dir)

from dotenv import load_dotenv  # noqa: E402

load_dotenv(os.path.join(_plugin_dir, ".env"))

from hooks.scan_staged_cli import cli_main  # noqa: E402
from hooks.scan_staged_cli import main as _cli_scan  # noqa: E402


def main() -> None:
    """Back-compat wrapper: exits rather than returning, as callers expect."""
    sys.exit(_cli_scan())


if __name__ == "__main__":
    cli_main()
