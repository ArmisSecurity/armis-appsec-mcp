"""Tests for hooks/hook_core.py shared gate logic."""

import hashlib
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import hook_core


class TestIsShippingCommand:
    @pytest.mark.parametrize(
        "cmd",
        [
            "git commit -m 'msg'",
            "git push",
            "git push origin main",
            "gh pr create --title 'PR'",
            "git add . && git commit -m 'msg'",
            "echo done; git push",
        ],
    )
    def test_shipping_commands(self, cmd):
        assert hook_core._is_shipping_command(cmd)

    @pytest.mark.parametrize(
        "cmd",
        ["git status", "git diff", "ls -la", "python app.py", "git add ."],
    )
    def test_non_shipping_commands(self, cmd):
        assert not hook_core._is_shipping_command(cmd)


class TestIsPushOrPr:
    def test_push(self):
        assert hook_core._is_push_or_pr("git push")
        assert hook_core._is_push_or_pr("git push origin main")

    def test_pr_create(self):
        assert hook_core._is_push_or_pr("gh pr create --title 'x'")

    def test_commit_is_not_push(self):
        assert not hook_core._is_push_or_pr("git commit -m 'x'")


class TestHasAllFlag:
    def test_short_flag(self):
        assert hook_core._has_all_flag("git commit -a -m 'msg'")

    def test_long_flag(self):
        assert hook_core._has_all_flag("git commit --all -m 'msg'")

    def test_no_flag(self):
        assert not hook_core._has_all_flag("git commit -m 'msg'")


class TestIsScanPassFile:
    def test_basename_match(self):
        assert hook_core.is_scan_pass_file("/some/path/.scan-pass")
        assert hook_core.is_scan_pass_file(".scan-pass")

    def test_not_scan_pass(self):
        assert not hook_core.is_scan_pass_file("/some/path/file.py")
        assert not hook_core.is_scan_pass_file("scan-pass")
        assert not hook_core.is_scan_pass_file("")
        assert not hook_core.is_scan_pass_file(None)


class TestCheckGate:
    def test_non_shipping_allows(self):
        result = hook_core.check_gate("git status")
        assert result.decision == "allow"
        assert result.system_message == ""

    def test_scan_pass_write_denies(self):
        result = hook_core.check_gate("echo hash > /path/.scan-pass")
        assert result.decision == "deny"
        assert "BLOCKED" in result.system_message

    def test_scan_pass_tee_denies(self):
        result = hook_core.check_gate("tee /path/.scan-pass")
        assert result.decision == "deny"
        assert "BLOCKED" in result.system_message

    def test_shipping_without_scan_pass_denies(self, tmp_path):
        os.environ["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)
        subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
        try:
            result = hook_core.check_gate("git commit -m 'msg'")
            assert result.decision == "deny"
            assert "Security scan required" in result.system_message
        finally:
            del os.environ["CLAUDE_PLUGIN_ROOT"]

    def test_shipping_with_valid_scan_pass_allows(self, tmp_path):
        subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=str(tmp_path),
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"],
            cwd=str(tmp_path),
            capture_output=True,
        )
        # Create a file, stage it, compute hash, write .scan-pass
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")
        subprocess.run(["git", "add", "test.py"], cwd=str(tmp_path), capture_output=True)
        diff_result = subprocess.run(
            ["git", "diff", "--cached", "--no-color", "--no-ext-diff"],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
        )
        staged_hash = hashlib.sha256(diff_result.stdout.encode()).hexdigest()
        (tmp_path / ".scan-pass").write_text(staged_hash)

        os.environ["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)
        old_cwd = os.getcwd()
        os.chdir(str(tmp_path))
        try:
            result = hook_core.check_gate("git commit -m 'msg'")
            assert result.decision == "allow"
        finally:
            os.chdir(old_cwd)
            del os.environ["CLAUDE_PLUGIN_ROOT"]


class TestBuildSystemMessage:
    def test_commit_gets_staged(self):
        msg = hook_core.build_system_message("git commit -m 'x'")
        assert "scan_diff(staged=True)" in msg

    def test_commit_a_gets_unstaged(self):
        msg = hook_core.build_system_message("git commit -a -m 'x'")
        assert "scan_diff()" in msg

    def test_push_gets_ref(self):
        msg = hook_core.build_system_message("git push")
        assert "scan_diff(ref='origin/HEAD')" in msg


class TestCrossAdapterInterop:
    """Verify .scan-pass written once is accepted by all adapter scripts."""

    def test_scan_pass_accepted_by_all_adapters(self, tmp_path):
        subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=str(tmp_path),
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"],
            cwd=str(tmp_path),
            capture_output=True,
        )
        test_file = tmp_path / "file.py"
        test_file.write_text("x = 1")
        subprocess.run(["git", "add", "file.py"], cwd=str(tmp_path), capture_output=True)
        diff_result = subprocess.run(
            ["git", "diff", "--cached", "--no-color", "--no-ext-diff"],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
        )
        staged_hash = hashlib.sha256(diff_result.stdout.encode()).hexdigest()
        (tmp_path / ".scan-pass").write_text(staged_hash)

        hooks_dir = os.path.join(os.path.dirname(__file__), "..")
        adapters = [
            ("pre_commit_scan.py", {"tool_input": {"command": "git commit -m 'x'"}}),
            (
                "gemini_pre_tool.py",
                {"tool_name": "shell", "tool_input": {"command": "git commit -m 'x'"}},
            ),
            (
                "codex_pre_tool.py",
                {"tool_name": "shell", "tool_input": {"command": "git commit -m 'x'"}},
            ),
            (
                "cursor_pre_tool.py",
                {"tool_name": "terminal", "tool_input": {"command": "git commit -m 'x'"}},
            ),
            (
                "copilot_pre_tool.py",
                {"toolName": "bash", "toolArgs": {"command": "git commit -m 'x'"}},
            ),
            (
                "cline_pre_tool.py",
                {"tool": {"name": "execute_command", "input": {"command": "git commit -m 'x'"}}},
            ),
        ]

        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)

        for script, payload in adapters:
            result = subprocess.run(
                [sys.executable, os.path.join(hooks_dir, script)],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
                cwd=str(tmp_path),
            )
            assert result.returncode == 0, f"{script} returned {result.returncode}: {result.stderr}"
