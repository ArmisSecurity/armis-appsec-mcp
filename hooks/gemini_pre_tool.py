#!/usr/bin/env python3
"""Gemini CLI BeforeTool hook -- Security gate for shipping commands.

Protocol: stdout JSON with {"decision": "allow"} or {"decision": "deny", "reason": "..."}.
Exit code is always 0 (Gemini uses JSON decision field, not exit codes for deny).
"""

import json
import os
import sys

_hooks_dir = os.path.dirname(os.path.abspath(__file__))
if _hooks_dir not in sys.path:
    sys.path.insert(0, _hooks_dir)

_ALLOW = json.dumps({"decision": "allow"})
_MAX_STDIN_BYTES = 1_048_576

_SHELL_TOOLS = {"shell", "bash", "run_shell_command", "terminal", "execute_command"}
_WRITE_TOOLS = {"write_file", "edit_file", "patch_file", "create_file", "replace"}


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

        tool_name = hook_input.get("tool_name", "")
        tool_input = hook_input.get("tool_input", {})
        if not isinstance(tool_input, dict):
            tool_input = {}

        if tool_name in _SHELL_TOOLS:
            cmd = tool_input.get("command", "")
            if not isinstance(cmd, str) or not cmd.strip():
                print(_ALLOW)
                sys.exit(0)
            result = check_gate(cmd)
            if result.decision == "deny":
                print(json.dumps({"decision": "deny", "reason": result.system_message}))
                sys.exit(0)

        elif tool_name in _WRITE_TOOLS:
            file_path = tool_input.get("file_path", tool_input.get("path", ""))
            if is_scan_pass_file(file_path):
                print(
                    json.dumps(
                        {
                            "decision": "deny",
                            "reason": (
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
