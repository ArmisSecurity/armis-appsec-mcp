"""Tests for hooks/gemini_pre_tool.py -- Gemini CLI BeforeTool adapter."""

import json
import os
import subprocess
import sys

import pytest

HOOK_PATH = os.path.join(os.path.dirname(__file__), "..", "gemini_pre_tool.py")


@pytest.fixture
def run_gemini_hook(tmp_path):
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)

    def _run(tool_name="run_shell_command", command="", file_path=None, env_override=None):
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
def run_gemini_hook_raw(tmp_path):
    """Run hook with arbitrary JSON payload."""
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


class TestShippingCommandsDeny:
    @pytest.mark.parametrize(
        "cmd",
        [
            "git commit -m 'feat: x'",
            "git push",
            "gh pr create --title 'PR'",
        ],
    )
    def test_shipping_commands_deny(self, run_gemini_hook, cmd):
        result = run_gemini_hook(tool_name="run_shell_command", command=cmd)
        assert result.returncode == 2
        assert "Security scan required" in result.stderr

    @pytest.mark.parametrize(
        "cmd",
        [
            "git commit -m 'feat: x'",
            "git push",
            "gh pr create --title 'PR'",
        ],
    )
    def test_deny_also_writes_json_stdout(self, run_gemini_hook, cmd):
        result = run_gemini_hook(tool_name="run_shell_command", command=cmd)
        assert result.returncode == 2
        data = json.loads(result.stdout)
        assert data["decision"] == "deny"
        assert "reason" in data
        assert "systemMessage" in data


class TestNonShippingAllow:
    @pytest.mark.parametrize(
        "cmd",
        ["git status", "ls -la", "python app.py", "git diff"],
    )
    def test_non_shipping_allows(self, run_gemini_hook, cmd):
        result = run_gemini_hook(tool_name="run_shell_command", command=cmd)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["decision"] == "allow"


class TestWriteToolGuard:
    def test_write_to_scan_pass_denied(self, run_gemini_hook):
        result = run_gemini_hook(tool_name="write_file", file_path="/project/.scan-pass")
        assert result.returncode == 2
        assert "BLOCKED" in result.stderr

    def test_replace_to_scan_pass_denied(self, run_gemini_hook):
        result = run_gemini_hook(tool_name="replace", file_path="/project/.scan-pass")
        assert result.returncode == 2
        assert "BLOCKED" in result.stderr

    def test_write_to_normal_file_allowed(self, run_gemini_hook):
        result = run_gemini_hook(tool_name="write_file", file_path="/project/app.py")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["decision"] == "allow"


class TestUnknownToolFallsToShellCheck:
    """If matcher fires but tool_name is unexpected, hook still checks command."""

    @pytest.mark.parametrize(
        "tool_name",
        [
            "shell",
            "bash",
            "terminal",
            "execute_command",
            "Shell",
            "unknown_tool",
        ],
    )
    def test_unexpected_tool_name_with_shipping_command_denies(self, run_gemini_hook, tool_name):
        result = run_gemini_hook(tool_name=tool_name, command="git commit -m 'feat: x'")
        assert result.returncode == 2
        assert "Security scan required" in result.stderr

    @pytest.mark.parametrize(
        "tool_name",
        ["shell", "terminal", "unknown_tool"],
    )
    def test_unexpected_tool_name_with_safe_command_allows(self, run_gemini_hook, tool_name):
        result = run_gemini_hook(tool_name=tool_name, command="git status")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["decision"] == "allow"


class TestAlternativeCommandFields:
    """Gemini uses 'command' but we also try 'cmd' for robustness."""

    def test_cmd_field_blocks_shipping(self, run_gemini_hook_raw):
        payload = {"tool_name": "run_shell_command", "tool_input": {"cmd": "git commit -m 'x'"}}
        result = run_gemini_hook_raw(payload)
        assert result.returncode == 2
        assert "Security scan required" in result.stderr

    def test_command_field_preferred_over_cmd(self, run_gemini_hook_raw):
        payload = {
            "tool_name": "run_shell_command",
            "tool_input": {"command": "git push", "cmd": "ls"},
        }
        result = run_gemini_hook_raw(payload)
        assert result.returncode == 2
        assert "Security scan required" in result.stderr


class TestNoCommandAllows:
    def test_empty_tool_input_allows(self, run_gemini_hook):
        result = run_gemini_hook(tool_name="run_shell_command", command="")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["decision"] == "allow"

    def test_missing_command_allows(self, run_gemini_hook_raw):
        payload = {"tool_name": "run_shell_command", "tool_input": {"description": "list files"}}
        result = run_gemini_hook_raw(payload)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["decision"] == "allow"


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
        assert data["decision"] == "allow"

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
        assert data["decision"] == "allow"


class TestDebugLogging:
    def test_debug_mode_logs_to_stderr_on_allow(self, run_gemini_hook):
        result = run_gemini_hook(
            tool_name="run_shell_command",
            command="git status",
            env_override={"APPSEC_DEBUG": "1"},
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["decision"] == "allow"
        assert "[appsec-gemini-hook]" in result.stderr

    def test_no_debug_no_stderr_on_allow(self, run_gemini_hook):
        result = run_gemini_hook(tool_name="run_shell_command", command="git status")
        assert result.returncode == 0
        assert result.stderr == ""
