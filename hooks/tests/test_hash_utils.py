"""Tests for hash_utils.resolve_scan_pass_path — the unified scan-pass resolver.

The resolver locates the scan-pass via `git rev-parse --absolute-git-dir`, so
the MCP server (writer) and the commit-gate hook (reader) always agree — even
inside git worktrees, where `.git` is a *file*, not a directory. The worktree
case is the one the old dual-resolver code got wrong (isdir vs exists), so it
gets dedicated coverage here.
"""

import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from hash_utils import (  # noqa: E402
    SCAN_PASS_BASENAME,
    cleanup_legacy_scan_pass,
    compute_staged_hash,
    resolve_scan_pass_path,
)


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, check=True)


@pytest.fixture()
def git_repo(tmp_path, monkeypatch):
    """Create a git repo in tmp_path and chdir into it."""
    _git(["init"], tmp_path)
    _git(["config", "user.email", "test@test.com"], tmp_path)
    _git(["config", "user.name", "Test"], tmp_path)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _expected_git_dir(repo):
    """The absolute git dir git itself reports for repo (symlink-resolved)."""
    return subprocess.run(
        ["git", "rev-parse", "--absolute-git-dir"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


class TestResolveScanPassPath:
    def test_resolves_into_git_dir(self, git_repo, monkeypatch):
        """Path is <absolute-git-dir>/armis-scan-pass, inside .git/."""
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
        result = resolve_scan_pass_path()
        assert result == os.path.join(_expected_git_dir(git_repo), SCAN_PASS_BASENAME)
        # Lives inside .git/ — never in the working tree.
        assert os.path.basename(result) == "armis-scan-pass"
        assert ".git" in result

    def test_ignores_claude_plugin_root(self, git_repo, monkeypatch, tmp_path):
        """CLAUDE_PLUGIN_ROOT is no longer consulted; the CWD git dir wins."""
        other = tmp_path.parent / "elsewhere"
        other.mkdir(exist_ok=True)
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(other))
        result = resolve_scan_pass_path()
        assert result == os.path.join(_expected_git_dir(git_repo), SCAN_PASS_BASENAME)

    def test_cwd_in_subdirectory_resolves_to_repo_git_dir(self, git_repo, monkeypatch):
        """CWD deep in the repo still resolves to the repo's git dir."""
        subdir = git_repo / "a" / "b" / "c"
        subdir.mkdir(parents=True)
        monkeypatch.chdir(subdir)
        result = resolve_scan_pass_path()
        assert result == os.path.join(_expected_git_dir(git_repo), SCAN_PASS_BASENAME)

    def test_not_a_git_repo_falls_back_to_plugin_dir(self, monkeypatch):
        """Outside any git repo, fall back to the plugin install dir."""
        import tempfile

        with tempfile.TemporaryDirectory() as isolated:
            monkeypatch.chdir(isolated)
            result = resolve_scan_pass_path()
        plugin_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        assert result == os.path.join(plugin_dir, SCAN_PASS_BASENAME)

    def test_repo_path_overrides_cwd(self, git_repo, monkeypatch, tmp_path):
        """resolve_scan_pass_path(repo_path) resolves against the *passed* repo,
        not the process CWD. This is the crux of the worktree handshake: the
        long-lived MCP server is pinned to a launch CWD that may be a sibling
        of the repo being committed, so it must resolve from the scanned
        repo_path. CWD points at git_repo; we resolve a *second* repo and
        expect the second repo's git dir to win."""
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
        other = tmp_path.parent / "other_repo"
        other.mkdir(exist_ok=True)
        _git(["init"], other)

        # CWD is git_repo, but we pass `other` — `other` must win.
        result = resolve_scan_pass_path(str(other))
        assert result == os.path.join(_expected_git_dir(other), SCAN_PASS_BASENAME)
        # And it must NOT be git_repo's path (the CWD repo).
        assert result != os.path.join(_expected_git_dir(git_repo), SCAN_PASS_BASENAME)

    def test_server_with_repo_path_matches_hook_in_worktree(self, git_repo, monkeypatch, tmp_path):
        """The end-to-end regression: a server pinned to the main repo, given
        repo_path=<worktree>, resolves the SAME scan-pass the hook resolves
        from inside that worktree. Before the fix the server used its own CWD
        and the two diverged, so the gate denied forever."""
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
        (git_repo / "seed.txt").write_text("seed")
        _git(["add", "seed.txt"], git_repo)
        _git(["commit", "-m", "seed"], git_repo)

        worktree = tmp_path.parent / "wt2"
        _git(["worktree", "add", str(worktree)], git_repo)
        try:
            # Server's CWD stays at the main repo (git_repo) — it is pinned.
            monkeypatch.chdir(git_repo)
            server_view = resolve_scan_pass_path(str(worktree))

            # Hook runs *inside* the worktree, resolving from CWD (no repo_path).
            monkeypatch.chdir(worktree)
            hook_view = resolve_scan_pass_path()

            assert server_view == hook_view
            assert "worktrees" in server_view  # the per-worktree git dir
        finally:
            monkeypatch.chdir(git_repo)
            _git(["worktree", "remove", "--force", str(worktree)], git_repo)

    def test_server_and_hook_resolve_same_path(self, git_repo, monkeypatch):
        """Regression: the gate reader (hook_core) and the writer (hash_utils)
        must resolve the SAME path. They previously diverged in worktrees."""
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)

        hooks_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "hooks",
        )
        if hooks_dir not in sys.path:
            sys.path.insert(0, hooks_dir)
        import hook_core

        # hook_core imports resolve_scan_pass_path from hash_utils — same source.
        assert hook_core.resolve_scan_pass_path() == resolve_scan_pass_path()


class TestWorktree:
    """The bug that motivated this change: in a git worktree `.git` is a file,
    not a directory, so the old filesystem walker (isdir) and the writer
    (exists) disagreed and the gate denied forever. With git-based resolution
    they agree."""

    def test_resolves_in_worktree(self, git_repo, monkeypatch, tmp_path):
        # Need a commit before `git worktree add` works.
        (git_repo / "seed.txt").write_text("seed")
        _git(["add", "seed.txt"], git_repo)
        _git(["commit", "-m", "seed"], git_repo)

        worktree = tmp_path.parent / "wt"
        _git(["worktree", "add", str(worktree)], git_repo)
        try:
            # `.git` in a worktree is a FILE, not a directory.
            assert (worktree / ".git").is_file()

            monkeypatch.chdir(worktree)
            monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)

            result = resolve_scan_pass_path()
            expected_git_dir = _expected_git_dir(worktree)

            # Resolves into the PER-WORKTREE git dir, not the shared common dir.
            assert result == os.path.join(expected_git_dir, SCAN_PASS_BASENAME)
            assert "worktrees" in expected_git_dir
            # And the writer can actually create it there.
            with open(result, "w") as f:
                f.write("deadbeef")
            assert os.path.isfile(result)
        finally:
            _git(["worktree", "remove", "--force", str(worktree)], git_repo)


class TestComputeStagedHashNonUtf8:
    """Regression: a staged file with non-UTF-8 bytes
    used to make compute_staged_hash() (text=True + .encode()) raise
    UnicodeDecodeError, which escaped the gate reader's `except OSError` and
    reached the hooks' outer fail-open catch-all → commit ALLOWED despite a
    stale/forged/absent pass. The hash now covers raw bytes and fails *closed*.
    """

    # A staged diff containing invalid UTF-8 bytes (\xe9\xff).
    _BAD_BYTES = b"first line\nx\xe9\xff bytes here\nlast\n"

    def test_hash_non_utf8_staged_diff_does_not_raise(self, git_repo):
        """compute_staged_hash returns a 64-char hex digest, not "" and no raise."""
        (git_repo / "weird.txt").write_bytes(self._BAD_BYTES)
        _git(["add", "weird.txt"], git_repo)

        digest = compute_staged_hash()
        assert isinstance(digest, str)
        assert len(digest) == 64
        int(digest, 16)  # valid hex

    def test_gate_denies_with_stale_pass_on_non_utf8(self, git_repo, monkeypatch):
        """A stale (non-matching) scan-pass must DENY (fail closed), not fail open."""
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
        (git_repo / "weird.txt").write_bytes(self._BAD_BYTES)
        _git(["add", "weird.txt"], git_repo)

        # Place a non-matching (stale/forged) scan-pass.
        scan_pass = resolve_scan_pass_path()
        with open(scan_pass, "w") as f:
            f.write("deadbeef" * 8)

        hooks_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "hooks",
        )
        if hooks_dir not in sys.path:
            sys.path.insert(0, hooks_dir)
        import hook_core

        # Must return False (deny) — never raise into the fail-open catch-all.
        assert hook_core._has_matching_scan_pass() is False

    def test_scan_staged_hash_matches_compute_staged_hash(self, git_repo):
        """The portable git-hook writer and the gate reader must agree on the
        byte-hash (INVARIANTS #4), including for non-UTF-8 content."""
        import hashlib

        (git_repo / "weird.txt").write_bytes(self._BAD_BYTES)
        _git(["add", "weird.txt"], git_repo)

        raw = subprocess.run(
            ["git", "diff", "--cached", "--no-color", "--no-ext-diff"],
            cwd=str(git_repo),
            capture_output=True,
        ).stdout
        # This is exactly what git-hooks/scan-staged.py now hashes.
        assert hashlib.sha256(raw).hexdigest() == compute_staged_hash()


class TestCleanupLegacyScanPass:
    def test_removes_legacy_working_tree_file(self, git_repo):
        legacy = git_repo / ".scan-pass"
        legacy.write_text("old-hash")
        cleanup_legacy_scan_pass()
        assert not legacy.exists()

    def test_noop_when_absent(self, git_repo):
        # Should not raise when there is nothing to clean up.
        cleanup_legacy_scan_pass()
        assert not (git_repo / ".scan-pass").exists()

    def test_noop_outside_git_repo(self, monkeypatch):
        import tempfile

        with tempfile.TemporaryDirectory() as isolated:
            monkeypatch.chdir(isolated)
            # No git repo → no toplevel → silently does nothing.
            cleanup_legacy_scan_pass()
