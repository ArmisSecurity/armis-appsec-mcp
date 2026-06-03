#!/usr/bin/env python3
"""Cursor preToolUse / beforeShellExecution hook -- Security gate for shipping commands.

Protocol:
- Allow: {"permission": "allow"} on stdout, exit 0
- Deny: {"permission": "deny", "agent_message": "..."} on stdout, exit 0
"""

import json
import os
import sys

_hooks_dir = os.path.dirname(os.path.abspath(__file__))
if _hooks_dir not in sys.path:
    sys.path.insert(0, _hooks_dir)

_ALLOW = json.dumps({"permission": "allow"})
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

        # Cursor's beforeShellExecution payload is FLAT — {command, cwd, ...}
        # with no tool_name/tool_input wrapper (bug-hunt #4). The preToolUse
        # write-guard path uses the wrapped {tool_name, tool_input} shape. Read
        # the command from either location so the gate fires on every shell
        # command regardless of which event invoked us. (The shell matcher in
        # cursor.hooks.json is ".*" so this adapter sees ALL shell commands; if
        # we gated on tool_name the forgery guard in check_gate would never run
        # for a bare `echo h > .git/armis-scan-pass`.)
        cmd = hook_input.get("command", "")
        if not isinstance(cmd, str) or not cmd.strip():
            cmd = tool_input.get("command", "")

        # Shell command present (flat beforeShellExecution, or a wrapped shell
        # tool): run the full gate, which covers both the shipping check and the
        # scan-pass anti-forgery check.
        if isinstance(cmd, str) and cmd.strip():
            result = check_gate(cmd)
            if result.decision == "deny":
                print(json.dumps({"permission": "deny", "agent_message": result.system_message}))
                sys.exit(0)

        # Write tool: check anti-forgery (preToolUse with a file-edit tool name)
        elif tool_name in ("Write", "Edit", "write_file", "edit_file"):
            file_path = tool_input.get("file_path", tool_input.get("path", ""))
            if is_scan_pass_file(file_path):
                print(
                    json.dumps(
                        {
                            "permission": "deny",
                            "agent_message": (
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
