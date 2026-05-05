"""Tests for server.py helpers: read_and_validate_file, run_git_diff, get_debug_config."""

import os
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

# Add plugin dir to path so we can import server module
_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

# Reuse the MCP mock from test_server_security if already loaded,
# otherwise set up our own. This ensures ToolError is the same class.
if "mcp.server.fastmcp" not in sys.modules:

    class _ToolError(Exception):
        pass

    _mock_exceptions = MagicMock()
    _mock_exceptions.ToolError = _ToolError
    _mock_fastmcp = MagicMock()
    _mock_fastmcp.exceptions = _mock_exceptions
    _mock_fastmcp.Context = MagicMock()
    sys.modules["mcp"] = MagicMock()
    sys.modules["mcp.server"] = MagicMock()
    sys.modules["mcp.server.fastmcp"] = _mock_fastmcp
    sys.modules["mcp.server.fastmcp.exceptions"] = _mock_exceptions

# Get the ToolError that server.py actually uses
_ToolError = sys.modules["mcp.server.fastmcp.exceptions"].ToolError

import importlib

if "server" in sys.modules:
    importlib.reload(sys.modules["server"])
import server


@pytest.fixture(autouse=True)
def _reset_allowed_roots():
    """Reset the lazy-init allowed roots cache between tests."""
    server._ALLOWED_ROOTS.clear()
    yield
    server._ALLOWED_ROOTS.clear()


# ---------------------------------------------------------------------------
# read_and_validate_file
# ---------------------------------------------------------------------------
class TestReadAndValidateFile:
    def test_happy_path(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("print('hello')\n")
        code, filename, resolved = server.read_and_validate_file(str(f))
        assert code == "print('hello')\n"
        assert filename == "app.py"
        assert resolved == os.path.realpath(str(f))

    def test_file_not_found(self, tmp_path):
        with pytest.raises(Exception, match="File not found"):
            server.read_and_validate_file(str(tmp_path / "nonexistent.py"))

    def test_file_too_large(self, tmp_path):
        f = tmp_path / "big.py"
        f.write_bytes(b"x" * (11 * 1024 * 1024))  # 11MB
        with pytest.raises(Exception, match="too large"):
            server.read_and_validate_file(str(f))

    def test_binary_file(self, tmp_path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"header\x00binary\x00data")
        with pytest.raises(Exception, match="binary"):
            server.read_and_validate_file(str(f))

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.py"
        f.write_text("")
        with pytest.raises(Exception, match="empty"):
            server.read_and_validate_file(str(f))

    def test_whitespace_only_file(self, tmp_path):
        f = tmp_path / "blank.py"
        f.write_text("   \n\n  \n")
        with pytest.raises(Exception, match="empty"):
            server.read_and_validate_file(str(f))

    def test_truncation(self, tmp_path):
        f = tmp_path / "huge.py"
        f.write_text("x" * 100_000)
        code, _, _ = server.read_and_validate_file(str(f))
        assert len(code) == server._MAX_CODE_CHARS

    def test_blocked_path(self):
        with pytest.raises(Exception, match="outside allowed"):
            server.read_and_validate_file("/etc/passwd")


# ---------------------------------------------------------------------------
# run_git_diff
# ---------------------------------------------------------------------------
class TestRunGitDiff:
    def test_invalid_ref(self):
        with pytest.raises(Exception, match="Invalid git ref"):
            server.run_git_diff(ref="ref; rm -rf /")

    def test_dash_prefix_ref(self):
        with pytest.raises(Exception, match="cannot start with"):
            server.run_git_diff(ref="--help")

    def test_empty_diff(self, tmp_path):
        # Create a git repo with no changes
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
        (tmp_path / "init.txt").write_text("init")
        subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "init"],
            cwd=str(tmp_path),
            capture_output=True,
        )
        result = server.run_git_diff(repo_path=str(tmp_path))
        assert result == ""

    def test_excludes_deleted_files_from_staged_diff(self, tmp_path):
        # Set up repo with a committed file, then stage its deletion
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
        (tmp_path / "to_delete.py").write_text("SECRET = 'oops'\n")
        subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "init"],
            cwd=str(tmp_path),
            capture_output=True,
        )
        subprocess.run(["git", "rm", "to_delete.py"], cwd=str(tmp_path), capture_output=True)
        result = server.run_git_diff(repo_path=str(tmp_path), staged=True)
        assert "to_delete.py" not in result
        assert "SECRET" not in result

    def test_includes_modified_but_not_deleted_in_staged_diff(self, tmp_path):
        # Set up repo with two files, modify one and delete the other
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
        (tmp_path / "keep.py").write_text("x = 1\n")
        (tmp_path / "remove.py").write_text("y = 2\n")
        subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "init"],
            cwd=str(tmp_path),
            capture_output=True,
        )
        # Modify keep.py and delete remove.py
        (tmp_path / "keep.py").write_text("x = 42\n")
        subprocess.run(["git", "rm", "remove.py"], cwd=str(tmp_path), capture_output=True)
        subprocess.run(["git", "add", "keep.py"], cwd=str(tmp_path), capture_output=True)
        result = server.run_git_diff(repo_path=str(tmp_path), staged=True)
        assert "keep.py" in result
        assert "x = 42" in result
        assert "remove.py" not in result

    def test_timeout(self):
        with patch("server.subprocess.run", side_effect=subprocess.TimeoutExpired("git", 30)):
            with pytest.raises(Exception, match="timed out"):
                server.run_git_diff()


# ---------------------------------------------------------------------------
# get_debug_config
# ---------------------------------------------------------------------------
class TestGetDebugConfig:
    def test_masks_credentials(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_ID", "abcdefgh")
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "secret-value")
        monkeypatch.setenv("APPSEC_ENV", "prod")

        with patch("server.get_auth_status", return_value="not yet exchanged"):
            result = server.get_debug_config()

        assert "abcd***" in result
        assert "abcdefgh" not in result
        assert "secret-value" not in result
        assert "Client Secret: set" in result

    def test_short_client_id(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_ID", "ab")
        monkeypatch.delenv("ARMIS_CLIENT_SECRET", raising=False)

        with patch("server.get_auth_status", return_value="not initialized"):
            result = server.get_debug_config()

        assert "Client ID: ab" in result
        assert "***" not in result
        assert "Client Secret: not set" in result


# ---------------------------------------------------------------------------
# compute_staged_hash
# ---------------------------------------------------------------------------
class TestComputeStagedHash:
    def test_git_failure_returns_empty(self):
        """Git returncode != 0 should return empty string (CWE-253 fix)."""
        from hash_utils import compute_staged_hash

        mock_result = MagicMock()
        mock_result.returncode = 128
        mock_result.stdout = "some output"
        with patch("hash_utils.subprocess.run", return_value=mock_result):
            assert compute_staged_hash() == ""

    def test_git_success_empty_stdout_returns_empty(self):
        """Successful git with no output means no staged changes."""
        from hash_utils import compute_staged_hash

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        with patch("hash_utils.subprocess.run", return_value=mock_result):
            assert compute_staged_hash() == ""

    def test_git_success_with_output_returns_hash(self):
        """Successful git with output returns SHA-256 hash."""
        import hashlib

        from hash_utils import compute_staged_hash

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "diff content here"
        with patch("hash_utils.subprocess.run", return_value=mock_result):
            result = compute_staged_hash()
            expected = hashlib.sha256(b"diff content here").hexdigest()
            assert result == expected


# ---------------------------------------------------------------------------
# get_debug_config (continued)
# ---------------------------------------------------------------------------
class TestGetDebugConfigNoCreds:
    def test_no_credentials(self, monkeypatch):
        monkeypatch.delenv("ARMIS_CLIENT_ID", raising=False)
        monkeypatch.delenv("ARMIS_CLIENT_SECRET", raising=False)

        with patch("server.get_auth_status", return_value="not initialized"):
            result = server.get_debug_config()

        assert "Client ID: not set" in result
        assert "Client Secret: not set" in result


# ---------------------------------------------------------------------------
# _cache_scan — ref-scan .scan-pass flow
# ---------------------------------------------------------------------------
class TestCacheScanRefScanPass:
    """Tests for ref-based scans writing .scan-pass (comments #8+#9 fix)."""

    def test_ref_scan_writes_scan_pass_when_clean(self, tmp_path, monkeypatch):
        """Clean ref scan with scan_hash should write .scan-pass."""
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        server._cache_scan(
            report="No findings",
            findings=[],
            filename="diff against origin/HEAD",
            is_staged_scan=True,
            scan_hash="abc123deadbeef",
        )
        scan_pass = tmp_path / ".scan-pass"
        assert scan_pass.exists()
        assert scan_pass.read_text() == "abc123deadbeef"

    def test_ref_scan_no_write_on_critical(self, tmp_path, monkeypatch):
        """Ref scan with CRITICAL findings should NOT write .scan-pass."""
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        server._cache_scan(
            report="Found issues",
            findings=[{"severity": "CRITICAL", "cwe": 79}],
            filename="diff against origin/HEAD",
            is_staged_scan=True,
            scan_hash="abc123deadbeef",
        )
        scan_pass = tmp_path / ".scan-pass"
        assert not scan_pass.exists()

    def test_ref_scan_removes_existing_pass_on_critical(self, tmp_path, monkeypatch):
        """Critical findings should remove an existing .scan-pass."""
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        scan_pass = tmp_path / ".scan-pass"
        scan_pass.write_text("old-hash")

        server._cache_scan(
            report="Found issues",
            findings=[{"severity": "HIGH", "cwe": 798}],
            filename="diff against origin/HEAD",
            is_staged_scan=True,
            scan_hash="abc123deadbeef",
        )
        assert not scan_pass.exists()

    def test_non_shipping_scan_does_not_write_pass(self, tmp_path, monkeypatch):
        """scan_code/scan_file should NOT write .scan-pass."""
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        server._cache_scan(
            report="No findings",
            findings=[],
            filename="snippet",
            is_staged_scan=False,
            scan_hash="",
        )
        scan_pass = tmp_path / ".scan-pass"
        assert not scan_pass.exists()

    def test_scan_hash_fallback_to_compute(self, tmp_path, monkeypatch):
        """When scan_hash is empty, falls back to compute_staged_hash()."""
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        with patch("server.compute_staged_hash", return_value="staged-hash-123"):
            server._cache_scan(
                report="No findings",
                findings=[],
                filename="staged changes",
                is_staged_scan=True,
                scan_hash="",
            )
        scan_pass = tmp_path / ".scan-pass"
        assert scan_pass.exists()
        assert scan_pass.read_text() == "staged-hash-123"
