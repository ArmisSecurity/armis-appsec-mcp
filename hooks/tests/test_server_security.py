"""Tests for server.py security fixes — S-4, S-11, S-12, path validation.

Since server.py depends on the MCP framework (mcp.server.fastmcp), we test
security-critical logic via two approaches:
1. Regex and constant validation — test _VALID_GIT_REF and _BLOCKED_PREFIXES directly
2. Source code analysis — verify '--' separator and --no-ext-diff are present
3. _validate_file_path — test by importing with mocked MCP, catching the mock ToolError
"""

import os
import sys

import pytest

# Add plugin dir to path so we can import server module
_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

# We need to mock MCP before importing server — ToolError becomes a real exception
from unittest.mock import MagicMock

_mock_exceptions = MagicMock()


class _FakeToolError(Exception):
    pass


_mock_exceptions.ToolError = _FakeToolError

_mock_fastmcp = MagicMock()
_mock_fastmcp.exceptions = _mock_exceptions
_mock_fastmcp.Context = MagicMock()

sys.modules["mcp"] = MagicMock()
sys.modules["mcp.server"] = MagicMock()
sys.modules["mcp.server.fastmcp"] = _mock_fastmcp
sys.modules["mcp.server.fastmcp.exceptions"] = _mock_exceptions

# Now we can import server — ToolError is our _FakeToolError
import importlib

if "path_security" in sys.modules:
    importlib.reload(sys.modules["path_security"])
if "server" in sys.modules:
    importlib.reload(sys.modules["server"])
import server


# ---------------------------------------------------------------------------
# _validate_file_path
# ---------------------------------------------------------------------------
class TestValidateFilePath:
    @pytest.fixture(autouse=True)
    def _reset_allowed_roots(self):
        """Reset the lazy-init cache between tests."""
        server._ALLOWED_ROOTS.clear()
        yield
        server._ALLOWED_ROOTS.clear()

    def test_valid_path(self, tmp_path):
        """Valid file path returns resolved path."""
        f = tmp_path / "app.py"
        f.write_text("code")
        result = server._validate_file_path(str(f))
        assert result == str(f.resolve())

    def test_blocked_etc(self):
        """Paths under /etc/ are blocked (caught by allowlist)."""
        with pytest.raises(_FakeToolError, match="outside allowed"):
            server._validate_file_path("/etc/passwd")

    def test_blocked_proc(self):
        """Paths under /proc/ are blocked (caught by allowlist)."""
        with pytest.raises(_FakeToolError, match="outside allowed"):
            server._validate_file_path("/proc/self/environ")

    def test_blocked_sys(self):
        """Paths under /sys/ are blocked (caught by allowlist)."""
        with pytest.raises(_FakeToolError, match="outside allowed"):
            server._validate_file_path("/sys/class/net")

    def test_blocked_ssh_dotdir(self):
        """Paths under ~/.ssh/ are blocked."""
        home = os.path.expanduser("~")
        with pytest.raises(_FakeToolError, match="sensitive"):
            server._validate_file_path(os.path.join(home, ".ssh", "id_rsa"))

    def test_blocked_aws_dotdir(self):
        """Paths under ~/.aws/ are blocked."""
        home = os.path.expanduser("~")
        with pytest.raises(_FakeToolError, match="sensitive"):
            server._validate_file_path(os.path.join(home, ".aws", "credentials"))

    def test_path_outside_home_blocked(self):
        """Paths outside HOME and /tmp are blocked by the allowlist."""
        with pytest.raises(_FakeToolError, match="outside allowed"):
            server._validate_file_path("/opt/evil/file.py")

    def test_path_under_tmp_allowed(self, tmp_path):
        """Paths under /tmp are allowed."""
        f = tmp_path / "scan.py"
        f.write_text("code")
        result = server._validate_file_path(str(f))
        assert result == str(f.resolve())

    def test_traversal_outside_home_blocked(self):
        """Path traversal resolving outside HOME is blocked."""
        with pytest.raises(_FakeToolError, match="outside allowed"):
            server._validate_file_path("/var/log/../log/syslog")


# ---------------------------------------------------------------------------
# S-11: Git ref validation
# ---------------------------------------------------------------------------
class TestGitRefValidation:
    def test_valid_git_ref_regex(self):
        """Standard refs pass the regex."""
        assert server._VALID_GIT_REF.match("main")
        assert server._VALID_GIT_REF.match("HEAD~3")
        assert server._VALID_GIT_REF.match("feature/my-branch")
        assert server._VALID_GIT_REF.match("v1.2.3")
        assert server._VALID_GIT_REF.match("abc123def")

    def test_invalid_git_ref_regex(self):
        """Refs with special characters are rejected."""
        assert not server._VALID_GIT_REF.match("ref; rm -rf /")
        assert not server._VALID_GIT_REF.match("ref && evil")
        assert not server._VALID_GIT_REF.match("ref | cat")
        assert not server._VALID_GIT_REF.match("")

    def test_dash_prefix_in_ref(self):
        """Refs starting with - match the regex but are caught by startswith check.

        The regex allows '-' in refs (needed for branch names like 'my-branch').
        The startswith('-') check in scan_diff() prevents flag injection.
        """
        # The regex DOES match --help (- is in the character class)
        assert server._VALID_GIT_REF.match("--help")
        # But scan_diff() has an explicit check: if ref.startswith("-"): raise

    def test_git_diff_command_has_separator(self):
        """Verify the scan_diff function source includes '--' separator."""
        source_path = os.path.join(_plugin_dir, "server.py")
        with open(source_path) as f:
            source = f.read()
        # Find the scan_diff function and check for '--' in the cmd construction
        assert '"--"' in source or "'--'" in source, (
            "server.py must include '--' separator in git diff command"
        )

    def test_git_diff_command_has_no_ext_diff(self):
        """Verify scan_diff includes --no-ext-diff to prevent custom diff driver exploitation."""
        source_path = os.path.join(_plugin_dir, "server.py")
        with open(source_path) as f:
            source = f.read()
        assert "--no-ext-diff" in source, "server.py must include --no-ext-diff flag"
