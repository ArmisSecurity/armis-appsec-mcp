#!/usr/bin/env python3
"""GitHub Copilot CLI preToolUse hook -- Security gate for shipping commands.

Protocol:
- Input: {"toolName": "bash", "toolArgs": {"command": "..."}, ...}
- Allow: {"permissionDecision": "allow"} on stdout, exit 0
- Deny: {"permissionDecision": "deny", "permissionDecisionReason": "..."} on stdout, exit 0
"""

import json
import os
import sys

_hooks_dir = os.path.dirname(os.path.abspath(__file__))
if _hooks_dir not in sys.path:
    sys.path.insert(0, _hooks_dir)

_ALLOW = json.dumps({"permissionDecision": "allow"})
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

        tool_name = hook_input.get("toolName", "")
        tool_args = hook_input.get("toolArgs", {})
        if not isinstance(tool_args, dict):
            tool_args = {}

        if tool_name in ("bash", "powershell", "shell", "terminal"):
            cmd = tool_args.get("command", "")
            if not isinstance(cmd, str) or not cmd.strip():
                print(_ALLOW)
                sys.exit(0)
            result = check_gate(cmd)
            if result.decision == "deny":
                print(
                    json.dumps(
                        {
                            "permissionDecision": "deny",
                            "permissionDecisionReason": result.system_message,
                        }
                    )
                )
                sys.exit(0)

        elif tool_name in ("create", "edit", "write", "write_file", "apply_patch"):
            file_path = tool_args.get("file_path", tool_args.get("path", ""))
            if is_scan_pass_file(file_path):
                print(
                    json.dumps(
                        {
                            "permissionDecision": "deny",
                            "permissionDecisionReason": (
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
