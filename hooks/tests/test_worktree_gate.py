"""End-to-end regression for the git-worktree commit-gate handshake.

The bug (reported twice): the MCP server is a long-lived process pinned to the
directory Claude Code launched it in -- in a Conductor setup, the *main*
checkout. The pre-commit gate hook runs fresh per Bash call in the user's CWD --
the *worktree*. Both resolve the scan-pass via `git rev-parse --absolute-git-dir`,
which returns the *per-worktree* git dir, so when their CWDs differ they resolve
two different files and the gate denies forever.

The fix: scan_diff threads its ``repo_path`` through to the scan-pass writer and
the staged-hash computation, so a server pinned to the main repo still writes
into the *worktree's* git dir when given ``repo_path=<worktree>``. These tests
exercise the real server.scan_diff + hook_core.check_gate path (only the API
call and git diff are mocked) and assert writer and reader meet.
"""

import json
import os
import subprocess
import sys

import pytest

_plugin_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)
_hooks_dir = os.path.join(_plugin_dir, "hooks")
if _hooks_dir not in sys.path:
    sys.path.insert(0, _hooks_dir)

import importlib  # noqa: E402
from unittest.mock import MagicMock, patch  # noqa: E402

# Stub the MCP framework the same way the other integration tests do, so
# importing server does not require the real runtime.
if "mcp.server.fastmcp" not in sys.modules:

    class _FakeToolError(Exception):
        pass

    _mock_exceptions = MagicMock()
    _mock_exceptions.ToolError = _FakeToolError
    _mock_fastmcp = MagicMock()
    _mock_fastmcp.exceptions = _mock_exceptions
    _mock_fastmcp.Context = MagicMock()
    sys.modules["mcp"] = MagicMock()
    sys.modules["mcp.server"] = MagicMock()
    sys.modules["mcp.server.fastmcp"] = _mock_fastmcp
    sys.modules["mcp.server.fastmcp.exceptions"] = _mock_exceptions

# Make @mcp.tool() an identity decorator so the real async tool coroutines
# (scan_diff) survive import and can be awaited directly -- otherwise the
# MagicMock-wrapped tool is not awaitable. Mirrors test_suppression_integration.
sys.modules["mcp.server.fastmcp"].FastMCP.return_value.tool.return_value = lambda f: f

import hook_core  # noqa: E402

if "server" in sys.modules:
    importlib.reload(sys.modules["server"])
import server  # noqa: E402


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, check=True)


def _clean_findings_json() -> str:
    return "```json\n[]\n```"


@pytest.fixture
def main_and_worktree(tmp_path, monkeypatch):
    """A real main repo with a linked worktree that has a staged change.

    Yields (main_repo, worktree). The autouse _ensure_tmp_is_git_repo fixture
    would `git init` tmp_path itself, so build the repos in subdirs.
    """
    main = tmp_path / "main"
    main.mkdir()
    _git(["init"], main)
    _git(["config", "user.email", "t@t.com"], main)
    _git(["config", "user.name", "T"], main)
    (main / "seed.txt").write_text("seed\n")
    _git(["add", "seed.txt"], main)
    _git(["commit", "-m", "seed"], main)

    worktree = tmp_path / "wt"
    _git(["worktree", "add", str(worktree)], main)
    # `.git` in a worktree is a FILE, not a directory -- the crux of the bug.
    assert (worktree / ".git").is_file()

    # Stage a change *in the worktree* only.
    (worktree / "feature.py").write_text("x = 1\n")
    _git(["add", "feature.py"], worktree)

    # Neutralize legacy cleanup so it never touches the real test CWD.
    monkeypatch.setattr(server, "cleanup_legacy_scan_pass", lambda *a, **k: None)
    return main, worktree


def _worktree_scan_pass(worktree) -> str:
    git_dir = subprocess.run(
        ["git", "rev-parse", "--absolute-git-dir"],
        cwd=str(worktree),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return os.path.join(git_dir, "armis-scan-pass")


class TestWorktreeHandshake:
    @pytest.mark.asyncio
    async def test_server_pinned_to_main_writes_into_worktree_git_dir(
        self, main_and_worktree, monkeypatch
    ):
        """scan_diff(staged=True, repo_path=<worktree>) called with CWD pinned to
        the MAIN repo must write the scan-pass into the WORKTREE's git dir."""
        main, worktree = main_and_worktree
        monkeypatch.chdir(main)  # server is pinned to the main checkout

        with patch("server.call_appsec_api", return_value=_clean_findings_json()):
            await server.scan_diff(repo_path=str(worktree), staged=True)

        wt_pass = _worktree_scan_pass(worktree)
        main_pass = os.path.join(
            subprocess.run(
                ["git", "rev-parse", "--absolute-git-dir"],
                cwd=str(main),
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip(),
            "armis-scan-pass",
        )
        assert os.path.isfile(wt_pass), "scan-pass should land in the worktree's git dir"
        assert not os.path.isfile(main_pass), "scan-pass must NOT land in the main repo"

    @pytest.mark.asyncio
    async def test_full_gate_allows_commit_after_pinned_scan(self, main_and_worktree, monkeypatch):
        """End-to-end: server pinned to main scans the worktree, then the gate
        running in the worktree allows the commit. Pre-fix this denied forever."""
        main, worktree = main_and_worktree

        # 1. Server (CWD = main repo) scans the worktree with repo_path.
        monkeypatch.chdir(main)
        with patch("server.call_appsec_api", return_value=_clean_findings_json()):
            await server.scan_diff(repo_path=str(worktree), staged=True)

        # 2. Hook fires in the worktree's CWD and reads the gate.
        monkeypatch.chdir(worktree)
        result = hook_core.check_gate("git commit -m 'feature'")
        assert result.decision == "allow", result.system_message

    @pytest.mark.asyncio
    async def test_omitting_repo_path_reproduces_the_bug(self, main_and_worktree, monkeypatch):
        """Control: WITHOUT repo_path the server scans its own (main) CWD, the
        worktree scan-pass is never written, and the gate denies -- the exact
        failure mode that was reported. This guards against a regression that
        silently drops the repo_path threading."""
        main, worktree = main_and_worktree

        # Server pinned to main, no repo_path: it scans main (nothing staged there).
        monkeypatch.chdir(main)
        with patch("server.call_appsec_api", return_value=_clean_findings_json()):
            await server.scan_diff(staged=True)

        # The worktree's scan-pass was never created.
        assert not os.path.isfile(_worktree_scan_pass(worktree))

        # So the gate, running in the worktree, denies.
        monkeypatch.chdir(worktree)
        result = hook_core.check_gate("git commit -m 'feature'")
        assert result.decision == "deny"

    def test_hook_injects_worktree_repo_path_into_instruction(self, main_and_worktree, monkeypatch):
        """The hook's deny message tells the agent to pass repo_path=<worktree>,
        closing the loop even when the agent omits it on the first try."""
        main, worktree = main_and_worktree
        monkeypatch.chdir(worktree)

        msg = hook_core.build_system_message("git commit -m 'x'")
        expected = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(worktree),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        assert f"scan_diff(staged=True, repo_path='{expected}')" in msg


class TestApproveFindingsWorktree:
    @pytest.mark.asyncio
    async def test_approve_writes_into_scanned_repo(self, main_and_worktree, monkeypatch):
        """approve_findings must write into the repo the last scan ran in, not
        the server's CWD -- otherwise the human-approved pass is invisible to
        the worktree gate."""
        main, worktree = main_and_worktree
        monkeypatch.chdir(main)

        high = '```json\n[{"cwe": 89, "severity": "HIGH", "line": 1, "explanation": "sqli"}]\n```'
        with patch("server.call_appsec_api", return_value=high):
            await server.scan_diff(repo_path=str(worktree), staged=True)

        # HIGH finding -> no auto-pass yet.
        assert not os.path.isfile(_worktree_scan_pass(worktree))

        result = server.do_approve_findings(reason="reviewed, false positive on test fixture")
        assert "Approved" in result, result
        assert os.path.isfile(_worktree_scan_pass(worktree)), (
            "approval scan-pass must land in the scanned worktree's git dir"
        )

        # And the gate in the worktree now allows.
        monkeypatch.chdir(worktree)
        gate = hook_core.check_gate("git commit -m 'x'")
        assert gate.decision == "allow", gate.system_message


def _run_pre_commit_hook(worktree, command):
    """Run the real pre_commit_scan.py subprocess in the worktree CWD."""
    hook = os.path.join(_hooks_dir, "pre_commit_scan.py")
    payload = {"tool_name": "Bash", "tool_input": {"command": command}}
    return subprocess.run(
        [sys.executable, hook],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
        cwd=str(worktree),
    )


class TestPreCommitSubprocessInWorktree:
    @pytest.mark.asyncio
    async def test_subprocess_hook_allows_after_pinned_scan(self, main_and_worktree, monkeypatch):
        """The real hook *subprocess* (fresh process, worktree CWD) allows the
        commit after a server pinned to main scanned the worktree -- the most
        faithful reproduction of the two-process setup."""
        main, worktree = main_and_worktree
        monkeypatch.chdir(main)
        with patch("server.call_appsec_api", return_value=_clean_findings_json()):
            await server.scan_diff(repo_path=str(worktree), staged=True)

        proc = _run_pre_commit_hook(worktree, "git commit -m 'feature'")
        assert proc.returncode == 0, f"hook denied: {proc.stderr}"
