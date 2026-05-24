"""Tests for hooks/cline_pre_tool.py -- Cline PreToolUse adapter."""

import json
import os
import subprocess
import sys

import pytest

HOOK_PATH = os.path.join(os.path.dirname(__file__), "..", "cline_pre_tool.py")


@pytest.fixture
def run_cline_hook(tmp_path):
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)

    def _run(tool_name="execute_command", command="", file_path=None, env_override=None):
        tool_input = {}
        if command:
            tool_input["command"] = command
        if file_path:
            tool_input["path"] = file_path
        hook_input = {"tool": {"name": tool_name, "input": tool_input}}

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


class TestShippingCommandsDeny:
    @pytest.mark.parametrize(
        "cmd",
        [
            "git commit -m 'feat: x'",
            "git push",
            "gh pr create --title 'PR'",
        ],
    )
    def test_shipping_commands_deny(self, run_cline_hook, cmd):
        result = run_cline_hook(tool_name="execute_command", command=cmd)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["cancel"] is True
        assert "Security scan required" in data["message"]


class TestNonShippingAllow:
    @pytest.mark.parametrize(
        "cmd",
        ["git status", "ls -la", "python app.py", "git diff"],
    )
    def test_non_shipping_allows(self, run_cline_hook, cmd):
        result = run_cline_hook(tool_name="execute_command", command=cmd)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data == {}


class TestWriteToolGuard:
    def test_write_to_scan_pass_denied(self, run_cline_hook):
        result = run_cline_hook(tool_name="write_to_file", file_path="/project/.scan-pass")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["cancel"] is True
        assert "BLOCKED" in data["message"]

    def test_replace_in_scan_pass_denied(self, run_cline_hook):
        result = run_cline_hook(tool_name="replace_in_file", file_path="/project/.scan-pass")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["cancel"] is True

    def test_write_to_normal_file_allowed(self, run_cline_hook):
        result = run_cline_hook(tool_name="write_to_file", file_path="/project/app.py")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data == {}


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
        assert data == {}

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
        assert data == {}
