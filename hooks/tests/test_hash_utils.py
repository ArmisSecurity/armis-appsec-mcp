"""Tests for hash_utils.resolve_scan_pass_path — the unified .scan-pass resolver."""

import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from hash_utils import resolve_scan_pass_path  # noqa: E402


@pytest.fixture()
def git_repo(tmp_path, monkeypatch):
    """Create a git repo in tmp_path and chdir into it."""
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)
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
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestResolveScanPassPath:
    def test_no_env_var_uses_cwd_git_root(self, git_repo, monkeypatch):
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
        result = resolve_scan_pass_path()
        assert result == os.path.join(str(git_repo), ".scan-pass")

    def test_env_var_set_uses_env_var(self, git_repo, monkeypatch):
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(git_repo))
        result = resolve_scan_pass_path()
        assert result == os.path.join(str(git_repo), ".scan-pass")

    def test_env_var_subdir_of_repo(self, git_repo, monkeypatch):
        subdir = git_repo / "subdir"
        subdir.mkdir()
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(subdir))
        result = resolve_scan_pass_path()
        assert result == os.path.join(str(subdir), ".scan-pass")

    def test_env_var_outside_git_falls_back_to_cwd(self, git_repo, monkeypatch, tmp_path):
        # Create a directory that is NOT inside any git repo
        import tempfile

        with tempfile.TemporaryDirectory() as isolated:
            monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", isolated)
            result = resolve_scan_pass_path()
            assert result == os.path.join(str(git_repo), ".scan-pass")

    def test_env_var_nonexistent_path_falls_back(self, git_repo, monkeypatch):
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", "/nonexistent/path/xyz")
        result = resolve_scan_pass_path()
        assert result == os.path.join(str(git_repo), ".scan-pass")

    def test_server_and_hooks_resolve_same_path(self, git_repo, monkeypatch):
        """Both resolve_scan_pass_path and hook_core.resolve_plugin_root agree."""
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)

        hooks_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "hooks",
        )
        if hooks_dir not in sys.path:
            sys.path.insert(0, hooks_dir)
        import hook_core

        server_path = resolve_scan_pass_path()
        hook_path = os.path.join(hook_core.resolve_plugin_root(), ".scan-pass")
        assert server_path == hook_path

    def test_cwd_in_subdirectory(self, git_repo, monkeypatch):
        """CWD deep in repo still resolves to repo root."""
        subdir = git_repo / "a" / "b" / "c"
        subdir.mkdir(parents=True)
        monkeypatch.chdir(subdir)
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
        result = resolve_scan_pass_path()
        assert result == os.path.join(str(git_repo), ".scan-pass")
