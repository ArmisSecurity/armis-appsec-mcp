"""Tests for protect_scan_pass.py hook — blocks Write/Edit to .scan-pass."""

import json
import os
import subprocess
import sys

HOOK_PATH = os.path.join(os.path.dirname(__file__), "..", "protect_scan_pass.py")


def _run_hook(hook_input, tmp_path):
    """Run protect_scan_pass.py as a subprocess and return (stdout, stderr, rc)."""
    env = os.environ.copy()
    env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)

    result = subprocess.run(
        [sys.executable, HOOK_PATH],
        input=json.dumps(hook_input) if hook_input is not None else "",
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


class TestBlocksScanPass:
    """Write/Edit to the scan-pass file must be denied (current + legacy names)."""

    def test_write_armis_scan_pass_blocked(self, tmp_path):
        stdin = {"tool_name": "Write", "tool_input": {"file_path": "armis-scan-pass"}}
        stdout, stderr, rc = _run_hook(stdin, tmp_path)
        assert rc == 2
        data = json.loads(stderr)
        assert data["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_write_armis_scan_pass_with_path_blocked(self, tmp_path):
        stdin = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/home/user/project/.git/armis-scan-pass"},
        }
        stdout, stderr, rc = _run_hook(stdin, tmp_path)
        assert rc == 2
        data = json.loads(stderr)
        assert data["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_write_scan_pass_blocked(self, tmp_path):
        stdin = {"tool_name": "Write", "tool_input": {"file_path": ".scan-pass"}}
        stdout, stderr, rc = _run_hook(stdin, tmp_path)
        assert rc == 2
        data = json.loads(stderr)
        assert data["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_write_scan_pass_with_path_blocked(self, tmp_path):
        stdin = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/home/user/project/.scan-pass"},
        }
        stdout, stderr, rc = _run_hook(stdin, tmp_path)
        assert rc == 2
        data = json.loads(stderr)
        assert data["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_edit_armis_scan_pass_blocked(self, tmp_path):
        stdin = {"tool_name": "Edit", "tool_input": {"file_path": "armis-scan-pass"}}
        stdout, stderr, rc = _run_hook(stdin, tmp_path)
        assert rc == 2

    def test_edit_scan_pass_blocked(self, tmp_path):
        stdin = {"tool_name": "Edit", "tool_input": {"file_path": ".scan-pass"}}
        stdout, stderr, rc = _run_hook(stdin, tmp_path)
        assert rc == 2

    def test_system_message_mentions_scan_diff(self, tmp_path):
        stdin = {"tool_name": "Write", "tool_input": {"file_path": ".scan-pass"}}
        _, stderr, _ = _run_hook(stdin, tmp_path)
        data = json.loads(stderr)
        assert "scan_diff()" in data["systemMessage"]


class TestAllowsNormalFiles:
    """Normal file operations must pass through."""

    def test_write_normal_file_allowed(self, tmp_path):
        stdin = {"tool_name": "Write", "tool_input": {"file_path": "normal.py"}}
        stdout, stderr, rc = _run_hook(stdin, tmp_path)
        assert rc == 0
        assert json.loads(stdout) == {}

    def test_edit_normal_file_allowed(self, tmp_path):
        stdin = {"tool_name": "Edit", "tool_input": {"file_path": "src/main.py"}}
        stdout, stderr, rc = _run_hook(stdin, tmp_path)
        assert rc == 0

    def test_file_containing_scan_pass_in_name_allowed(self, tmp_path):
        stdin = {
            "tool_name": "Write",
            "tool_input": {"file_path": "test_scan_pass_stuff.py"},
        }
        stdout, stderr, rc = _run_hook(stdin, tmp_path)
        assert rc == 0


class TestFailOpen:
    """Malformed input must always allow through (fail-open)."""

    def test_empty_input(self, tmp_path):
        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)
        result = subprocess.run(
            [sys.executable, HOOK_PATH],
            input="",
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        assert result.returncode == 0

    def test_invalid_json(self, tmp_path):
        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)
        result = subprocess.run(
            [sys.executable, HOOK_PATH],
            input="not json at all",
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        assert result.returncode == 0

    def test_missing_file_path(self, tmp_path):
        stdin = {"tool_name": "Write", "tool_input": {"content": "hello"}}
        stdout, stderr, rc = _run_hook(stdin, tmp_path)
        assert rc == 0

    def test_file_path_is_int(self, tmp_path):
        stdin = {"tool_name": "Write", "tool_input": {"file_path": 42}}
        stdout, stderr, rc = _run_hook(stdin, tmp_path)
        assert rc == 0

    def test_file_path_is_none(self, tmp_path):
        stdin = {"tool_name": "Write", "tool_input": {"file_path": None}}
        stdout, stderr, rc = _run_hook(stdin, tmp_path)
        assert rc == 0

    def test_tool_input_is_not_dict(self, tmp_path):
        stdin = {"tool_name": "Write", "tool_input": "a string"}
        stdout, stderr, rc = _run_hook(stdin, tmp_path)
        assert rc == 0

    def test_hook_input_is_not_dict(self, tmp_path):
        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)
        result = subprocess.run(
            [sys.executable, HOOK_PATH],
            input=json.dumps([1, 2, 3]),
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        assert result.returncode == 0
