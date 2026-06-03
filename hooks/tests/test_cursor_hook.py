"""Tests for hooks/cursor_pre_tool.py -- Cursor preToolUse adapter."""

import json
import os
import subprocess
import sys

import pytest

HOOK_PATH = os.path.join(os.path.dirname(__file__), "..", "cursor_pre_tool.py")


@pytest.fixture
def run_cursor_hook(tmp_path):
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)

    def _run(tool_name="terminal", command="", file_path=None, env_override=None):
        tool_input = {}
        if command:
            tool_input["command"] = command
        if file_path:
            tool_input["file_path"] = file_path
        hook_input = {"tool_name": tool_name, "tool_input": tool_input}

        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)
        if env_override:
            env.update(env_override)

        result = subprocess.run(
            [sys.executable, HOOK_PATH],
            input=json.dumps(hook_input),
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
            cwd=str(tmp_path),
        )
        return result

    return _run


@pytest.fixture
def run_cursor_hook_raw(tmp_path):
    """Run the hook with an arbitrary JSON payload (e.g. Cursor's real flat
    beforeShellExecution shape, which has no tool_name/tool_input wrapper)."""
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)

    def _run(payload: dict, env_override=None):
        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)
        if env_override:
            env.update(env_override)
        result = subprocess.run(
            [sys.executable, HOOK_PATH],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
            cwd=str(tmp_path),
        )
        return result

    return _run


class TestBeforeShellExecutionFlatPayload:
    """Bug-hunt #4: Cursor's beforeShellExecution payload is FLAT
    ({command, cwd, sandbox, hook_event_name}), with no tool_name/tool_input.
    The adapter previously only ran the gate when tool_name was a shell name,
    so the real payload fell through to ALLOW for every shell command."""

    def test_flat_shipping_command_denies(self, run_cursor_hook_raw):
        payload = {
            "command": "git commit -m 'feat: x'",
            "cwd": "/project",
            "hook_event_name": "beforeShellExecution",
        }
        result = run_cursor_hook_raw(payload)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "deny"
        assert "Security scan required" in data["agent_message"]

    def test_flat_safe_command_allows(self, run_cursor_hook_raw):
        payload = {"command": "git status", "cwd": "/project"}
        result = run_cursor_hook_raw(payload)
        assert result.returncode == 0
        assert json.loads(result.stdout)["permission"] == "allow"

    @pytest.mark.parametrize(
        "cmd",
        [
            "echo deadbeef > .git/armis-scan-pass",  # redirect forgery
            "dd of=.git/armis-scan-pass",  # dd forgery
            "echo h > .scan-pass",  # legacy name
        ],
    )
    def test_flat_scan_pass_forgery_denied(self, run_cursor_hook_raw, cmd):
        # The whole point of #4: a scan-pass write via shell must reach the
        # adapter (catch-all matcher) and be denied by check_gate's forgery guard.
        payload = {"command": cmd, "hook_event_name": "beforeShellExecution"}
        result = run_cursor_hook_raw(payload)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "deny"
        assert "BLOCKED" in data["agent_message"]


class TestShippingCommandsDeny:
    @pytest.mark.parametrize(
        "cmd",
        [
            "git commit -m 'feat: x'",
            "git push",
            "gh pr create --title 'PR'",
        ],
    )
    def test_shipping_commands_deny(self, run_cursor_hook, cmd):
        result = run_cursor_hook(tool_name="terminal", command=cmd)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "deny"
        assert "Security scan required" in data["agent_message"]


class TestNonShippingAllow:
    @pytest.mark.parametrize(
        "cmd",
        ["git status", "ls -la", "python app.py", "git diff"],
    )
    def test_non_shipping_allows(self, run_cursor_hook, cmd):
        result = run_cursor_hook(tool_name="terminal", command=cmd)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "allow"


class TestWriteToolGuard:
    def test_write_to_scan_pass_denied(self, run_cursor_hook):
        result = run_cursor_hook(tool_name="Write", file_path="/project/.scan-pass")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "deny"
        assert "BLOCKED" in data["agent_message"]

    def test_write_to_normal_file_allowed(self, run_cursor_hook):
        result = run_cursor_hook(tool_name="Write", file_path="/project/app.py")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "allow"


class TestFailOpen:
    def test_empty_stdin(self, tmp_path):
        subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)
        result = subprocess.run(
            [sys.executable, HOOK_PATH],
            input="",
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
            cwd=str(tmp_path),
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "allow"

    def test_invalid_json(self, tmp_path):
        subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)
        result = subprocess.run(
            [sys.executable, HOOK_PATH],
            input="not json{{{",
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
            cwd=str(tmp_path),
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "allow"
