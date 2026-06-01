#!/usr/bin/env python3
"""Gemini CLI BeforeTool hook -- Security gate for shipping commands.

Protocol (per Gemini CLI docs):
- Allow: {"decision": "allow"} on stdout, exit 0
- Deny (hard block): reason on stderr, exit 2
  Also writes full JSON to stdout as belt-and-suspenders.
"""

import json
import os
import sys

_hooks_dir = os.path.dirname(os.path.abspath(__file__))
if _hooks_dir not in sys.path:
    sys.path.insert(0, _hooks_dir)

_ALLOW = json.dumps({"decision": "allow"})
_MAX_STDIN_BYTES = 1_048_576

_WRITE_TOOLS = {"write_file", "replace", "create_file"}

_COMMAND_FIELDS = ("command", "cmd")

# "scan-pass" (no leading dot) matches both ".scan-pass" (legacy) and
# "armis-scan-pass" (current) as substrings.
_FAST_SHIP_KEYWORDS = ("git commit", "git push", "gh pr create", "scan-pass")
_SCAN_PASS_NAMES = ("armis-scan-pass", ".scan-pass")  # noqa: S105

_DEBUG = bool(os.environ.get("APPSEC_DEBUG"))


def _debug(msg: str) -> None:
    if _DEBUG:
        sys.stderr.write(f"[appsec-gemini-hook] {msg}\n")
        sys.stderr.flush()


def _deny(reason: str) -> None:
    """Deny via exit code 2 (hard block). Reason goes to stderr AND stdout JSON."""
    sys.stderr.write(reason)
    sys.stderr.flush()
    print(json.dumps({"decision": "deny", "reason": reason, "systemMessage": reason}))
    sys.exit(2)


def _extract_command(tool_input: dict) -> str:
    for field in _COMMAND_FIELDS:
        val = tool_input.get(field, "")
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def main():
    try:
        raw = sys.stdin.buffer.read(_MAX_STDIN_BYTES).decode("utf-8", errors="replace")
        hook_input = json.loads(raw) if raw.strip() else {}
        if not isinstance(hook_input, dict):
            hook_input = {}
    except Exception as e:
        _debug(f"stdin parse error: {e}")
        hook_input = {}

    _debug(f"received: tool_name={hook_input.get('tool_name', '<missing>')}")

    try:
        tool_name = hook_input.get("tool_name", "")
        tool_input = hook_input.get("tool_input", {})
        if not isinstance(tool_input, dict):
            tool_input = {}

        # Fast path: write-tool anti-forgery (pure string check, no imports needed)
        if tool_name in _WRITE_TOOLS:
            file_path = tool_input.get("file_path", tool_input.get("path", ""))
            _debug(f"write-tool check: tool={tool_name}, path={file_path}")
            if os.path.basename(file_path) in _SCAN_PASS_NAMES:
                _deny(
                    "BLOCKED: Direct writes to the scan-pass file are not allowed. "
                    "Run scan_diff() to scan your code instead."
                )
            print(_ALLOW)
            sys.exit(0)

        # Fast path: extract command and skip non-shipping commands immediately
        cmd = _extract_command(tool_input)
        _debug(f"shell-tool check: tool={tool_name}, cmd={cmd!r:.200}")
        if not cmd:
            _debug("no command extracted, allowing")
            print(_ALLOW)
            sys.exit(0)

        if not any(kw in cmd for kw in _FAST_SHIP_KEYWORDS):
            _debug("fast-path: not a shipping command, allowing")
            print(_ALLOW)
            sys.exit(0)

        # Slow path: shipping command detected, import gate logic (runs git subprocess)
        from hook_core import check_gate  # noqa: E402

        result = check_gate(cmd)
        if result.decision == "deny":
            _debug(f"DENY: {result.system_message[:100]}")
            _deny(result.system_message)

        _debug("gate passed, allowing")
        print(_ALLOW)
        sys.exit(0)

    except ImportError as e:
        _debug(f"CRITICAL: cannot import hook_core: {e}")
        print(_ALLOW)
        sys.exit(0)
    except Exception as e:
        _debug(f"operational error (fail-open): {type(e).__name__}: {e}")
        print(_ALLOW)
        sys.exit(0)


if __name__ == "__main__":
    main()
