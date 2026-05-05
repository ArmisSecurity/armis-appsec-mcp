"""Integration tests for scan pipeline and .scan-pass behavior.

Tests the _cache_scan function and the scan-pass forgery prevention
(scan_code/scan_file must NOT write .scan-pass, only scan_diff with staged=True).

These are sync tests that directly invoke server internals since the MCP
async tools require the full MCP framework runtime.
"""

import hashlib
import os
import subprocess
import sys
from unittest.mock import patch

import pytest

# Add plugin dir to path
_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from unittest.mock import MagicMock

# Reuse MCP mock if already loaded
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

import importlib

if "server" in sys.modules:
    importlib.reload(sys.modules["server"])
import server

# Clean and finding scan responses
_CLEAN_FINDINGS: list[dict] = []
_HIGH_FINDINGS = [{"cwe": 89, "severity": "HIGH", "line": 10, "explanation": "SQL injection"}]


@pytest.fixture
def plugin_root(tmp_path):
    """Set CLAUDE_PLUGIN_ROOT to a temp dir for .scan-pass isolation."""
    old = os.environ.get("CLAUDE_PLUGIN_ROOT")
    os.environ["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)
    yield tmp_path
    if old is not None:
        os.environ["CLAUDE_PLUGIN_ROOT"] = old
    else:
        os.environ.pop("CLAUDE_PLUGIN_ROOT", None)


def _init_git_repo(path):
    """Create a git repo with staged changes, return staged diff hash."""
    subprocess.run(["git", "init"], cwd=str(path), capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "t@t.com"],
        cwd=str(path),
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "T"],
        cwd=str(path),
        capture_output=True,
    )
    (path / "init.txt").write_text("init")
    subprocess.run(["git", "add", "."], cwd=str(path), capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(path), capture_output=True)
    (path / "new.py").write_text("print('hello')\n")
    subprocess.run(["git", "add", "new.py"], cwd=str(path), capture_output=True)
    result = subprocess.run(
        ["git", "diff", "--cached", "--no-color"],
        cwd=str(path),
        capture_output=True,
        text=True,
    )
    return hashlib.sha256(result.stdout.encode()).hexdigest()


# ---------------------------------------------------------------------------
# .scan-pass forgery prevention (Issue 9)
# ---------------------------------------------------------------------------
class TestScanPassForgeryPrevention:
    """_cache_scan must only write .scan-pass when is_staged_scan=True."""

    def test_cache_scan_without_staged_flag_does_not_write(self, plugin_root):
        """scan_code/scan_file path: is_staged_scan=False -> no .scan-pass."""
        server._cache_scan("clean report", _CLEAN_FINDINGS, "snippet.py")
        scan_pass = plugin_root / ".scan-pass"
        assert not scan_pass.exists(), "_cache_scan with is_staged_scan=False wrote .scan-pass"

    def test_cache_scan_with_staged_flag_writes(self, plugin_root, tmp_path):
        """scan_diff(staged=True) path: is_staged_scan=True -> writes .scan-pass."""
        staged_hash = _init_git_repo(tmp_path)

        # Run _cache_scan from within the git repo so compute_staged_hash works
        original_cwd = os.getcwd()
        try:
            os.chdir(str(tmp_path))
            server._cache_scan(
                "clean report",
                _CLEAN_FINDINGS,
                "staged changes",
                is_staged_scan=True,
            )
        finally:
            os.chdir(original_cwd)

        scan_pass = plugin_root / ".scan-pass"
        assert scan_pass.exists(), "_cache_scan with is_staged_scan=True should write .scan-pass"
        assert scan_pass.read_text().strip() == staged_hash

    def test_cache_scan_with_findings_removes_scan_pass(self, plugin_root, tmp_path):
        """HIGH findings + is_staged_scan=True -> removes existing .scan-pass."""
        _init_git_repo(tmp_path)
        (plugin_root / ".scan-pass").write_text("old-hash")

        original_cwd = os.getcwd()
        try:
            os.chdir(str(tmp_path))
            server._cache_scan(
                "findings report",
                _HIGH_FINDINGS,
                "staged changes",
                is_staged_scan=True,
            )
        finally:
            os.chdir(original_cwd)

        scan_pass = plugin_root / ".scan-pass"
        assert not scan_pass.exists(), ".scan-pass should be removed when HIGH findings are present"

    def test_cache_scan_updates_last_scan_cache(self):
        """_cache_scan always updates the in-memory cache regardless of is_staged_scan."""
        server._last_scan.update(
            {
                "report": "",
                "findings": [],
                "filename": "",
                "timestamp": None,
                "is_staged_scan": False,
            }
        )
        server._cache_scan("test report", _CLEAN_FINDINGS, "test.py")
        assert server._last_scan["report"] == "test report"
        assert server._last_scan["filename"] == "test.py"
        assert server._last_scan["timestamp"] is not None
        assert server._last_scan["is_staged_scan"] is False

        server._cache_scan("staged report", _CLEAN_FINDINGS, "staged.py", is_staged_scan=True)
        assert server._last_scan["is_staged_scan"] is True


# ---------------------------------------------------------------------------
# get_debug_config
# ---------------------------------------------------------------------------
class TestGetDebugConfig:
    def test_masks_long_client_id(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_ID", "test1234")
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "secret-value")
        with patch("server.get_auth_status", return_value="valid"):
            result = server.get_debug_config()
        assert "test***" in result
        assert "test1234" not in result
        assert "Client Secret: set" in result

    def test_shows_short_client_id_unmasked(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_ID", "ab")
        monkeypatch.delenv("ARMIS_CLIENT_SECRET", raising=False)
        with patch("server.get_auth_status", return_value="not initialized"):
            result = server.get_debug_config()
        assert "Client ID: ab" in result
        assert "Client Secret: not set" in result

    def test_missing_credentials(self, monkeypatch):
        monkeypatch.delenv("ARMIS_CLIENT_ID", raising=False)
        monkeypatch.delenv("ARMIS_CLIENT_SECRET", raising=False)
        with patch("server.get_auth_status", return_value="not initialized"):
            result = server.get_debug_config()
        assert "Client ID: not set" in result


# ---------------------------------------------------------------------------
# read_and_validate_file + run_git_diff integration
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# approve_findings escape hatch
# ---------------------------------------------------------------------------
_MEDIUM_FINDINGS = [{"cwe": 79, "severity": "MEDIUM", "line": 5, "explanation": "XSS risk"}]


class TestApproveFindings:
    """do_approve_findings must only work after a scan with HIGH/CRITICAL findings."""

    def test_writes_scan_pass_after_high_findings(self, plugin_root, tmp_path):
        """After scanning with HIGH findings, do_approve_findings writes .scan-pass."""
        staged_hash = _init_git_repo(tmp_path)

        original_cwd = os.getcwd()
        try:
            os.chdir(str(tmp_path))
            # Simulate a scan that found HIGH findings (deletes .scan-pass)
            server._cache_scan(
                "findings report",
                _HIGH_FINDINGS,
                "staged changes",
                is_staged_scan=True,
            )
            assert not (plugin_root / ".scan-pass").exists()

            # Now approve
            result = server.do_approve_findings(reason="false positives on deleted code")
        finally:
            os.chdir(original_cwd)

        assert "Approved 1 HIGH/CRITICAL" in result
        scan_pass = plugin_root / ".scan-pass"
        assert scan_pass.exists()
        assert scan_pass.read_text().strip() == staged_hash

    def test_without_prior_scan_fails(self):
        """do_approve_findings with no prior scan returns error."""
        server._last_scan.update(
            {
                "report": "",
                "findings": [],
                "filename": "",
                "timestamp": None,
                "is_staged_scan": False,
            }
        )
        result = server.do_approve_findings(reason="test reason")
        assert "ERROR" in result
        assert "not a shipping scan" in result

    def test_empty_reason_fails(self, plugin_root, tmp_path):
        """do_approve_findings with empty reason returns error."""
        _init_git_repo(tmp_path)
        server._cache_scan("findings report", _HIGH_FINDINGS, "staged changes", is_staged_scan=True)

        result = server.do_approve_findings(reason="   ")
        assert "ERROR" in result
        assert "reason is required" in result

    def test_only_medium_findings_fails(self):
        """do_approve_findings with only MEDIUM findings returns error."""
        server._cache_scan("medium report", _MEDIUM_FINDINGS, "staged changes", is_staged_scan=True)
        result = server.do_approve_findings(reason="test reason")
        assert "ERROR" in result
        assert "No HIGH/CRITICAL findings" in result

    def test_non_staged_scan_fails(self):
        """do_approve_findings after scan_code (not staged) returns error."""
        server._cache_scan("report", _HIGH_FINDINGS, "snippet.py", is_staged_scan=False)
        result = server.do_approve_findings(reason="bypass attempt")
        assert "ERROR" in result
        assert "not a shipping scan" in result


class TestReadAndValidateFileIntegration:
    def test_reads_real_file(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 1\n")
        code, name, resolved = server.read_and_validate_file(str(f))
        assert code == "x = 1\n"
        assert name == "test.py"
        assert resolved == os.path.realpath(str(f))


class TestRunGitDiffIntegration:
    def test_returns_diff_from_real_repo(self, tmp_path):
        _init_git_repo(tmp_path)
        # Run with staged=True to get the staged diff
        diff = server.run_git_diff(repo_path=str(tmp_path), staged=True)
        assert "new.py" in diff
        assert "print('hello')" in diff
