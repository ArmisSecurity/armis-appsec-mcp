#!/usr/bin/env python3
"""
Claude Code PreToolUse Hook -- Security gate for shipping commands.

Fires before every Bash tool execution. Inspects the command and blocks
git commit, git push, and gh pr create until code has been scanned.

Uses "exit 2 + stderr JSON" to deny the command and inject a systemMessage
telling Claude to scan first, then retry the original command.
"""

import json
import os
import sys

# Add hooks dir to path so we can import hook_core
_hooks_dir = os.path.dirname(os.path.abspath(__file__))
if _hooks_dir not in sys.path:
    sys.path.insert(0, _hooks_dir)

from hook_core import (  # noqa: E402
    GateResult,
    _has_all_flag,  # noqa: F401
    _is_push_or_pr,  # noqa: F401
    _is_shipping_command,  # noqa: F401
    check_gate,
    is_scan_pass_file,  # noqa: F401
)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
_MAX_STDIN_BYTES = 1_048_576  # 1MB — hook input is small JSON


def main():
    try:
        raw = sys.stdin.buffer.read(_MAX_STDIN_BYTES).decode("utf-8", errors="replace")
        hook_input = json.loads(raw) if raw.strip() else {}
        if not isinstance(hook_input, dict):
            hook_input = {}
    except Exception:
        hook_input = {}

    try:
        tool_input = hook_input.get("tool_input", {})
        if not isinstance(tool_input, dict):
            tool_input = {}

        cmd = tool_input.get("command", "")
        if not isinstance(cmd, str) or not cmd.strip():
            print(json.dumps({}))
            sys.exit(0)

        result: GateResult = check_gate(cmd)

        if result.decision == "deny":
            sys.stderr.write(
                json.dumps(
                    {
                        "hookSpecificOutput": {"permissionDecision": "deny"},
                        "systemMessage": result.system_message,
                    }
                )
            )
            sys.exit(2)

        print(json.dumps({}))
        sys.exit(0)

    except Exception:
        print(
            "appsec-hook: fail-open on internal error",
            file=sys.stderr,
        )
        print(json.dumps({}))
        sys.exit(0)


if __name__ == "__main__":
    main()
