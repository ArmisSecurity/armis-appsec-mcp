#!/usr/bin/env python3
"""Codex CLI PreToolUse hook -- Security gate for shipping commands.

Protocol: Same as Claude Code (Codex adopted the same format).
- Allow: {} on stdout, exit 0
- Deny: {"hookSpecificOutput": {"permissionDecision": "deny", ...}} on stderr, exit 2
"""

import json
import os
import sys

_hooks_dir = os.path.dirname(os.path.abspath(__file__))
if _hooks_dir not in sys.path:
    sys.path.insert(0, _hooks_dir)

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

        tool_input = hook_input.get("tool_input", {})
        if not isinstance(tool_input, dict):
            tool_input = {}

        tool_name = hook_input.get("tool_name", "")

        # Shell tool: check commit gate
        if tool_name in ("shell", "bash", "Bash", "terminal"):
            cmd = tool_input.get("command", "")
            if not isinstance(cmd, str) or not cmd.strip():
                print(json.dumps({}))
                sys.exit(0)
            result = check_gate(cmd)
            if result.decision == "deny":
                sys.stderr.write(
                    json.dumps(
                        {
                            "hookSpecificOutput": {
                                "permissionDecision": "deny",
                                "permissionDecisionReason": result.system_message,
                            },
                        }
                    )
                )
                sys.exit(2)

        # Write tool: check anti-forgery
        elif tool_name in ("write_file", "apply_patch", "edit_file", "Write", "Edit"):
            file_path = tool_input.get("file_path", tool_input.get("path", ""))
            if is_scan_pass_file(file_path):
                sys.stderr.write(
                    json.dumps(
                        {
                            "hookSpecificOutput": {
                                "permissionDecision": "deny",
                                "permissionDecisionReason": (
                                    "BLOCKED: Direct writes to .scan-pass are not allowed. "
                                    "Run scan_diff() to scan your code instead."
                                ),
                            },
                        }
                    )
                )
                sys.exit(2)

        print(json.dumps({}))
        sys.exit(0)

    except Exception:
        print(json.dumps({}))
        sys.exit(0)


if __name__ == "__main__":
    main()
