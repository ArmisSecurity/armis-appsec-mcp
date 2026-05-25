#!/usr/bin/env python3
"""Cline PreToolUse hook -- Security gate for shipping commands.

Protocol:
- Input: {"event": "PreToolUse", "tool": {"name": "execute_command", "input": {...}}}
- Allow: {} on stdout, exit 0
- Deny: {"cancel": true, "message": "..."} on stdout, exit 0
"""

import json
import os
import sys

_hooks_dir = os.path.dirname(os.path.abspath(__file__))
if _hooks_dir not in sys.path:
    sys.path.insert(0, _hooks_dir)

_ALLOW = json.dumps({})
_MAX_STDIN_BYTES = 1_048_576


def main():
    try:
        raw = sys.stdin.buffer.read(_MAX_STDIN_BYTES).decode("utf-8", errors="replace")
        hook_input = json.loads(raw) if raw.strip() else {}
        if not isinstance(hook_input, dict):
            hook_input = {}
    except Exception:
        hook_input = {}

    try:
        from hook_core import check_gate, is_scan_pass_file  # noqa: E402

        tool = hook_input.get("tool", {})
        if not isinstance(tool, dict):
            tool = {}

        tool_name = tool.get("name", "")
        tool_input = tool.get("input", {})
        if not isinstance(tool_input, dict):
            tool_input = {}

        if tool_name in ("execute_command", "shell", "bash", "terminal"):
            cmd = tool_input.get("command", "")
            if not isinstance(cmd, str) or not cmd.strip():
                print(_ALLOW)
                sys.exit(0)
            result = check_gate(cmd)
            if result.decision == "deny":
                print(json.dumps({"cancel": True, "message": result.system_message}))
                sys.exit(0)

        elif tool_name in ("write_to_file", "replace_in_file", "write", "edit"):
            file_path = tool_input.get("path", tool_input.get("file_path", ""))
            if is_scan_pass_file(file_path):
                print(
                    json.dumps(
                        {
                            "cancel": True,
                            "message": (
                                "BLOCKED: Direct writes to .scan-pass are not allowed. "
                                "Run scan_diff() to scan your code instead."
                            ),
                        }
                    )
                )
                sys.exit(0)

        print(_ALLOW)
        sys.exit(0)

    except Exception:
        print(_ALLOW)
        sys.exit(0)


if __name__ == "__main__":
    main()
