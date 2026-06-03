"""Integration tests for suppression wiring in server.py and scanner_core.py."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

# MCP mock setup (same pattern as test_server_helpers.py)
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

_ToolError = sys.modules["mcp.server.fastmcp.exceptions"].ToolError

# Make @mcp.tool() an identity decorator so the real async tool coroutines
# (e.g. scan_diff) survive import and can be awaited directly (eng-review D1).
# The real FastMCP.tool() likewise returns the function unchanged after
# registering it. Configured on the shared mock so reloads keep it.
sys.modules["mcp.server.fastmcp"].FastMCP.return_value.tool.return_value = lambda f: f

import importlib

if "server" in sys.modules:
    importlib.reload(sys.modules["server"])
import server
from scanner_core import format_findings
from suppression import ArmisIgnoreConfig, filter_diff_excluded_paths


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset server state between tests."""
    server._ALLOWED_ROOTS.clear()
    server._last_scan.update(
        {
            "report": "",
            "findings": [],
            "suppressed": [],
            "suppression_summary": {},
            "filename": "",
            "timestamp": None,
            "is_staged_scan": False,
            "scan_hash": "",
        }
    )
    yield
    server._ALLOWED_ROOTS.clear()


# ---------------------------------------------------------------------------
# Category E: _run_scan with suppression
# ---------------------------------------------------------------------------
class TestRunScanSuppression:
    @pytest.mark.asyncio
    async def test_suppresses_matching_findings(self):
        """_run_scan with config suppresses matching CWE findings."""
        raw_response = (
            '```json\n[{"cwe": 798, "severity": "HIGH", "line": 5, '
            '"explanation": "hardcoded secret", "has_secret": true}, '
            '{"cwe": 89, "severity": "HIGH", "line": 10, '
            '"explanation": "SQL injection", "has_secret": false}]\n```'
        )
        config = ArmisIgnoreConfig(cwes=[798])

        with patch("server.call_appsec_api", return_value=raw_response):
            report = await server._run_scan("code", "app.py", config=config)

        assert "SQL injection" in report
        assert "hardcoded secret" not in report
        assert "1 suppressed" in report

    @pytest.mark.asyncio
    async def test_no_config_loads_from_git(self):
        """_run_scan with config=None loads .armisignore from git root."""
        raw_response = (
            '```json\n[{"cwe": 89, "severity": "HIGH", "line": 1,'
            ' "explanation": "SQLi", "has_secret": false}]\n```'
        )

        with patch("server.call_appsec_api", return_value=raw_response):
            with patch("server.find_git_root", return_value=None):
                with patch("server.load_armisignore", return_value=ArmisIgnoreConfig()):
                    report = await server._run_scan("code", "app.py")

        assert "SQLi" in report

    @pytest.mark.asyncio
    async def test_critical_suppression_warning(self):
        """Suppressed CRITICAL emits a warning via logger."""
        raw_response = (
            '```json\n[{"cwe": 798, "severity": "CRITICAL", "line": 5, '
            '"explanation": "hardcoded key", "has_secret": true}]\n```'
        )
        config = ArmisIgnoreConfig(cwes=[798])

        with patch("server.call_appsec_api", return_value=raw_response):
            with patch("server.logger") as mock_logger:
                await server._run_scan("code", "app.py", config=config)

        mock_logger.warning.assert_called_once()
        assert "CRITICAL" in mock_logger.warning.call_args[0][0]


# ---------------------------------------------------------------------------
# Category E: scan_file path exclusion
# ---------------------------------------------------------------------------
class TestScanFilePathExclusion:
    def test_is_path_excluded_integration(self, tmp_path):
        """Path exclusion check works end-to-end with parsed .armisignore."""
        armisignore = tmp_path / ".armisignore"
        armisignore.write_text("vendor/\n*.generated.js\n")

        from suppression import is_path_excluded, load_armisignore

        config = load_armisignore(str(tmp_path))

        # vendor/ path excluded
        assert is_path_excluded(str(tmp_path / "vendor" / "lib.py"), config, str(tmp_path))
        # src/ path not excluded
        assert not is_path_excluded(str(tmp_path / "src" / "app.py"), config, str(tmp_path))
        # Generated file excluded
        assert is_path_excluded(str(tmp_path / "bundle.generated.js"), config, str(tmp_path))
        # Normal JS file not excluded
        assert not is_path_excluded(str(tmp_path / "app.js"), config, str(tmp_path))


# ---------------------------------------------------------------------------
# Category E: _cache_scan with suppression data
# ---------------------------------------------------------------------------
class TestCacheScanSuppression:
    def test_stores_suppressed_findings(self):
        """_cache_scan stores suppressed findings in _last_scan."""
        suppressed = [{"cwe": 798, "severity": "HIGH"}]
        summary = {"total": 2, "active": 1, "suppressed": 1, "by_directive": {"cwe:798": 1}}

        server._cache_scan(
            report="1 finding",
            findings=[{"cwe": 89, "severity": "HIGH"}],
            filename="app.py",
            suppressed=suppressed,
            suppression_summary=summary,
        )

        assert server._last_scan["suppressed"] == suppressed
        assert server._last_scan["suppression_summary"] == summary

    def test_suppressed_critical_blocks_scan_pass(self, isolated_server_scan_pass):
        """Suppressed CRITICAL findings prevent the scan-pass from being written."""
        suppressed = [{"cwe": 798, "severity": "CRITICAL"}]

        server._cache_scan(
            report="0 active findings",
            findings=[],
            filename="staged changes",
            is_staged_scan=True,
            scan_hash="abc123",
            suppressed=suppressed,
            suppression_summary={"total": 1, "active": 0, "suppressed": 1, "by_directive": {}},
        )

        assert not isolated_server_scan_pass.exists()

    def test_suppressed_high_does_not_block_scan_pass(self, isolated_server_scan_pass):
        """Suppressed HIGH findings do NOT block the scan-pass (only CRITICAL)."""
        suppressed = [{"cwe": 89, "severity": "HIGH"}]

        server._cache_scan(
            report="0 active findings",
            findings=[],
            filename="staged changes",
            is_staged_scan=True,
            scan_hash="abc123",
            suppressed=suppressed,
            suppression_summary={"total": 1, "active": 0, "suppressed": 1, "by_directive": {}},
        )

        assert isolated_server_scan_pass.exists()
        assert isolated_server_scan_pass.read_text() == "abc123"


# ---------------------------------------------------------------------------
# Category E: approve_findings with suppressed CRITICAL
# ---------------------------------------------------------------------------
class TestApproveFindingsSuppressedCritical:
    def test_suppressed_critical_requires_approval(self, isolated_server_scan_pass):
        """Suppressed CRITICAL findings still require approve_findings."""
        server._last_scan.update(
            {
                "findings": [],
                "suppressed": [{"cwe": 798, "severity": "CRITICAL"}],
                "is_staged_scan": True,
                "scan_hash": "hash123",
            }
        )
        with patch("server.compute_staged_hash", return_value="hash123"):
            result = server.do_approve_findings("user accepts risk")

        assert "Approved" in result
        assert isolated_server_scan_pass.exists()

    def test_no_findings_no_suppressed_critical_errors(self):
        """No active HIGH/CRITICAL + no suppressed CRITICAL → error."""
        server._last_scan.update(
            {
                "findings": [],
                "suppressed": [{"cwe": 79, "severity": "LOW"}],
                "is_staged_scan": True,
                "scan_hash": "hash123",
            }
        )
        result = server.do_approve_findings("reason")
        assert "ERROR" in result


# ---------------------------------------------------------------------------
# Category E: scan_diff path exclusion (tests the wiring logic via helpers)
# ---------------------------------------------------------------------------
class TestScanDiffPathExclusion:
    def test_all_excluded_writes_scan_pass(self, tmp_path, isolated_server_scan_pass):
        """When filter_diff_excluded_paths removes all files, _cache_scan writes the scan-pass."""
        diff_text = (
            "diff --git a/vendor/lib.js b/vendor/lib.js\n"
            "index 1234..5678 100644\n"
            "--- a/vendor/lib.js\n"
            "+++ b/vendor/lib.js\n"
            "@@ -1 +1 @@\n"
            "+vendored code\n"
        )
        config = ArmisIgnoreConfig(file_patterns=["vendor/"])

        # Simulate scan_diff's logic: filter → all excluded → _cache_scan
        filtered = filter_diff_excluded_paths(diff_text, config, str(tmp_path))
        assert filtered.strip() == ""

        label = "staged changes"
        scan_hash = "abc123staged"
        report = f"SCAN {label}: all changed files excluded by .armisignore"
        server._cache_scan(report, [], label, is_staged_scan=True, scan_hash=scan_hash)

        assert isolated_server_scan_pass.exists()
        assert isolated_server_scan_pass.read_text() == scan_hash

    def test_partial_exclusion_filters_diff(self, tmp_path):
        """filter_diff_excluded_paths removes excluded files, keeps the rest."""
        diff_text = (
            "diff --git a/vendor/lib.js b/vendor/lib.js\n"
            "--- a/vendor/lib.js\n"
            "+++ b/vendor/lib.js\n"
            "@@ -1 +1 @@\n"
            "+vendored\n"
            "diff --git a/src/app.py b/src/app.py\n"
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ -1 +1 @@\n"
            "+import os\n"
        )
        config = ArmisIgnoreConfig(file_patterns=["vendor/"])
        filtered = filter_diff_excluded_paths(diff_text, config, str(tmp_path))

        assert "vendor/lib.js" not in filtered
        assert "src/app.py" in filtered

    @pytest.mark.asyncio
    async def test_partial_exclusion_sends_filtered_to_api(self, tmp_path):
        """_run_scan receives only the filtered diff content."""
        diff_text = (
            "diff --git a/vendor/lib.js b/vendor/lib.js\n"
            "--- a/vendor/lib.js\n"
            "+++ b/vendor/lib.js\n"
            "@@ -1 +1 @@\n"
            "+vendored\n"
            "diff --git a/src/app.py b/src/app.py\n"
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ -1 +1 @@\n"
            "+import os\n"
        )
        config = ArmisIgnoreConfig(file_patterns=["vendor/"])
        filtered = filter_diff_excluded_paths(diff_text, config, str(tmp_path))
        raw_response = "```json\n[]\n```"

        with patch("server.call_appsec_api", return_value=raw_response) as mock_api:
            await server._run_scan(filtered, "staged changes", config=config)

        called_code = mock_api.call_args[0][0]
        assert "vendor/lib.js" not in called_code
        assert "src/app.py" in called_code

    def test_no_patterns_returns_unchanged(self, tmp_path):
        """No file_patterns in config → filter_diff_excluded_paths returns unchanged."""
        diff_text = "diff --git a/vendor/lib.js b/vendor/lib.js\n+++ b/vendor/lib.js\n+code\n"
        config = ArmisIgnoreConfig(cwes=[798])
        filtered = filter_diff_excluded_paths(diff_text, config, str(tmp_path))
        assert filtered == diff_text


# ---------------------------------------------------------------------------
# Category E: format_findings with suppression summary
# ---------------------------------------------------------------------------
class TestFormatFindingsWithSuppression:
    def test_shows_suppression_counts_in_header(self):
        findings = [{"cwe": 89, "severity": "HIGH", "line": 10, "explanation": "SQLi"}]
        summary = {"total": 2, "active": 1, "suppressed": 1, "by_directive": {"cwe:798": 1}}
        result = format_findings(findings, "app.py", suppression_summary=summary)
        assert "1 active, 1 suppressed" in result
        assert "1 by cwe:798" in result

    def test_all_suppressed_shows_zero_active(self):
        summary = {"total": 2, "active": 0, "suppressed": 2, "by_directive": {"severity:LOW": 2}}
        result = format_findings([], "app.py", suppression_summary=summary)
        assert "0 finding(s) (2 suppressed by .armisignore)" in result

    def test_no_suppression_backward_compatible(self):
        findings = [{"cwe": 89, "severity": "HIGH", "line": 10, "explanation": "SQLi"}]
        result = format_findings(findings, "app.py")
        assert "SCAN app.py: 1 finding(s)" in result
        assert "suppressed" not in result

    def test_no_findings_no_suppression(self):
        result = format_findings([], "app.py")
        assert result == "SCAN app.py: clean, no findings."


# ---------------------------------------------------------------------------
# Category E: Inline armis:ignore integration tests
# ---------------------------------------------------------------------------
class TestInlineSuppressionIntegration:
    @pytest.mark.asyncio
    async def test_scan_file_inline_suppression(self, tmp_path):
        """scan_file with inline armis:ignore suppresses matching findings."""
        raw_response = (
            '```json\n[{"cwe": 798, "severity": "HIGH", "line": 1, '
            '"explanation": "hardcoded secret", "has_secret": true, '
            '"confidence": 0.9, "cwe_name": "Use of Hard-coded Credentials", '
            '"tainted_function_references": []}]\n```'
        )
        config = ArmisIgnoreConfig()
        source_lines = ["password = 'secret'  # armis:ignore cwe:798"]

        with patch("server.call_appsec_api", return_value=raw_response):
            report = await server._run_scan(
                "password = 'secret'",
                "app.py",
                config=config,
                file_path=str(tmp_path / "app.py"),
                source_lines=source_lines,
            )

        assert "hardcoded secret" not in report
        assert "suppressed" in report
        assert "armis:ignore inline" in report

    @pytest.mark.asyncio
    async def test_scan_code_no_inline(self):
        """scan_code (no file_path) skips inline suppression."""
        raw_response = (
            '```json\n[{"cwe": 798, "severity": "HIGH", "line": 1, '
            '"explanation": "hardcoded", "has_secret": true, '
            '"confidence": 0.9, "cwe_name": "Hardcoded", '
            '"tainted_function_references": []}]\n```'
        )
        config = ArmisIgnoreConfig()

        with patch("server.call_appsec_api", return_value=raw_response):
            report = await server._run_scan("code", "snippet", config=config)

        assert "hardcoded" in report

    @pytest.mark.asyncio
    async def test_combined_armisignore_and_inline(self, tmp_path, monkeypatch):
        """Both .armisignore and inline suppression are reported."""
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        raw_response = (
            "```json\n["
            '{"cwe": 798, "severity": "HIGH", "line": 1, '
            '"explanation": "hardcoded", "has_secret": true, '
            '"confidence": 0.9, "cwe_name": "Hardcoded", '
            '"tainted_function_references": []},'
            '{"cwe": 89, "severity": "HIGH", "line": 2, '
            '"explanation": "sqli", "has_secret": false, '
            '"confidence": 0.9, "cwe_name": "SQLi", '
            '"tainted_function_references": []}'
            "]\n```"
        )
        config = ArmisIgnoreConfig(cwes=[798])
        source_lines = [
            "password = 'secret'",
            "query = f'{input}'  # armis:ignore cwe:89",
        ]

        with patch("server.call_appsec_api", return_value=raw_response):
            report = await server._run_scan(
                "code",
                "app.py",
                config=config,
                file_path=str(tmp_path / "app.py"),
                source_lines=source_lines,
            )

        assert "0 finding(s)" in report
        assert ".armisignore" in report
        assert "armis:ignore inline" in report

    @pytest.mark.asyncio
    async def test_inline_critical_still_blocks_scan_pass(
        self, tmp_path, isolated_server_scan_pass
    ):
        """Inline-suppressed CRITICAL findings still block the scan-pass."""
        raw_response = (
            '```json\n[{"cwe": 798, "severity": "CRITICAL", "line": 1, '
            '"explanation": "critical secret", "has_secret": true, '
            '"confidence": 0.9, "cwe_name": "Hardcoded", '
            '"tainted_function_references": []}]\n```'
        )
        config = ArmisIgnoreConfig()
        source_lines = ["password = 'admin'  # armis:ignore"]

        with patch("server.call_appsec_api", return_value=raw_response):
            await server._run_scan(
                "code",
                "staged changes",
                config=config,
                file_path=str(tmp_path / "app.py"),
                source_lines=source_lines,
                is_staged_scan=True,
                scan_hash="hash123",
            )

        assert not isolated_server_scan_pass.exists()

    def test_suppression_metadata_uniform(self, tmp_path):
        """Both armisignore and inline suppressed findings have metadata keys (D5)."""
        from suppression import apply_inline_suppressions, apply_suppressions

        findings = [
            {"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 1},
            {"cwe": 89, "severity": "HIGH", "has_secret": False, "line": 2},
        ]
        config = ArmisIgnoreConfig(cwes=[798])
        active, suppressed_armis, _ = apply_suppressions(findings, config)
        assert suppressed_armis[0]["_suppression_source"] == "armisignore"
        assert suppressed_armis[0]["_suppressed_by"] == "cwe:798"

        source_lines = ["x = 1", "query = f'{x}'  # armis:ignore cwe:89"]
        still_active, suppressed_inline = apply_inline_suppressions(
            active, str(tmp_path / "app.py"), source_lines
        )
        assert suppressed_inline[0]["_suppression_source"] == "inline"
        assert "armis:ignore" in suppressed_inline[0]["_suppressed_by"]

    def test_format_findings_backward_compat_no_by_inline(self):
        """format_findings with no by_inline key produces unchanged output (D6)."""
        summary = {"total": 2, "active": 1, "suppressed": 1, "by_directive": {"cwe:798": 1}}
        findings = [{"cwe": 89, "severity": "HIGH", "line": 10, "explanation": "SQLi"}]
        result = format_findings(findings, "app.py", suppression_summary=summary)
        assert "armis:ignore inline" not in result
        assert "1 by cwe:798" in result

    def test_format_findings_inline_only(self):
        """format_findings with only inline suppressions shows correct message."""
        summary = {"total": 2, "active": 1, "suppressed": 1, "by_directive": {}, "by_inline": 1}
        findings = [{"cwe": 89, "severity": "HIGH", "line": 10, "explanation": "SQLi"}]
        result = format_findings(findings, "app.py", suppression_summary=summary)
        assert "1 by armis:ignore inline" in result

    def test_format_findings_all_suppressed_inline_only(self):
        """All findings suppressed by inline → correct message."""
        summary = {"total": 2, "active": 0, "suppressed": 2, "by_directive": {}, "by_inline": 2}
        result = format_findings([], "app.py", suppression_summary=summary)
        assert "2 suppressed by armis:ignore inline" in result


# ---------------------------------------------------------------------------
# Category F: scan_diff inline armis:ignore suppression (PPSC-903 regression)
# ---------------------------------------------------------------------------
def _blob_line(diff_text: str, needle: str) -> int:
    """1-based blob line number of the line containing ``needle``."""
    for i, line in enumerate(diff_text.splitlines(), start=1):
        if needle in line:
            return i
    raise AssertionError(f"needle {needle!r} not found in diff")


def _findings_json(findings: list[dict]) -> str:
    """Wrap findings in the ```json fenced block parse_findings expects."""
    import json

    return f"```json\n{json.dumps(findings)}\n```"


class TestScanDiffInlineSuppression:
    """scan_diff must honor inline armis:ignore directives in the diff blob.

    Patches server.run_git_diff (crafted diff) + server.call_appsec_api (findings
    whose blob line lands on the directive). Blob lines are located via
    build_diff_line_map so offsets are not hardcoded.
    """

    _DIFF = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -0,0 +1,2 @@\n"
        '+password = "secret"  # armis:ignore cwe:798\n'
        '+query = f"SELECT {x}"\n'
    )

    def _finding(self, needle, **overrides):
        line = _blob_line(self._DIFF, needle)
        f = {
            "cwe": 798,
            "severity": "HIGH",
            "line": line,
            "explanation": "hardcoded secret",
            "has_secret": True,
        }
        f.update(overrides)
        return f

    @pytest.mark.asyncio
    async def test_scan_diff_suppresses_inline(self):
        """REGRESSION (#11): scan_diff applies inline armis:ignore (it did not before)."""
        raw = _findings_json([self._finding("password")])
        with patch("server.run_git_diff", return_value=self._DIFF):
            with patch("server.find_git_root", return_value=None):
                with patch("server.load_armisignore", return_value=ArmisIgnoreConfig()):
                    with patch("server.call_appsec_api", return_value=raw):
                        report = await server.scan_diff(repo_path="/x")

        assert "hardcoded secret" not in report
        assert "armis:ignore inline" in report

    @pytest.mark.asyncio
    async def test_scan_diff_non_matching_cwe_not_suppressed(self):
        """A directive cwe:798 does not suppress a cwe:89 finding on the same line."""
        raw = _findings_json(
            [self._finding("password", cwe=89, explanation="sqli", has_secret=False)]
        )
        with patch("server.run_git_diff", return_value=self._DIFF):
            with patch("server.find_git_root", return_value=None):
                with patch("server.load_armisignore", return_value=ArmisIgnoreConfig()):
                    with patch("server.call_appsec_api", return_value=raw):
                        report = await server.scan_diff(repo_path="/x")

        assert "sqli" in report

    @pytest.mark.asyncio
    async def test_inline_critical_still_blocks_scan_pass(self, isolated_server_scan_pass):
        """Inline-suppressed CRITICAL must NOT write .scan-pass (still needs approval)."""
        raw = _findings_json(
            [self._finding("password", severity="CRITICAL", explanation="critical secret")]
        )
        with patch("server.run_git_diff", return_value=self._DIFF):
            with patch("server.find_git_root", return_value=None):
                with patch("server.load_armisignore", return_value=ArmisIgnoreConfig()):
                    with patch("server.call_appsec_api", return_value=raw):
                        with patch("server.compute_staged_hash", return_value="hash123"):
                            await server.scan_diff(repo_path="/x", staged=True)

        assert not isolated_server_scan_pass.exists()

    @pytest.mark.asyncio
    async def test_inline_high_does_not_block_scan_pass(self, isolated_server_scan_pass):
        """Inline-suppressed HIGH (no other findings) writes .scan-pass."""
        raw = _findings_json([self._finding("password", severity="HIGH")])
        with patch("server.run_git_diff", return_value=self._DIFF):
            with patch("server.find_git_root", return_value=None):
                with patch("server.load_armisignore", return_value=ArmisIgnoreConfig()):
                    with patch("server.call_appsec_api", return_value=raw):
                        with patch("server.compute_staged_hash", return_value="hash123"):
                            await server.scan_diff(repo_path="/x", staged=True)

        assert isolated_server_scan_pass.exists()
        assert isolated_server_scan_pass.read_text().strip() == "hash123"

    @pytest.mark.asyncio
    async def test_combined_armisignore_and_inline(self):
        """Both .armisignore (cwe:89) and inline (cwe:798) suppress in one diff."""
        raw = _findings_json(
            [
                self._finding("password"),  # cwe 798 -> inline
                # cwe 89 -> .armisignore
                self._finding("query", cwe=89, explanation="sqli", has_secret=False),
            ]
        )
        config = ArmisIgnoreConfig(cwes=[89])
        with patch("server.run_git_diff", return_value=self._DIFF):
            with patch("server.find_git_root", return_value="/x"):
                with patch("server.load_armisignore", return_value=config):
                    with patch("server.call_appsec_api", return_value=raw):
                        report = await server.scan_diff(repo_path="/x")

        assert "0 finding(s)" in report
        assert ".armisignore" in report
        assert "armis:ignore inline" in report


class TestMergeInlineSuppressions:
    """_merge_inline_suppressions bookkeeping (shared by _run_scan and scan_diff)."""

    def test_merges_counts(self):
        summary = {"total": 3, "active": 3, "suppressed": 0, "by_directive": {}}
        inline = [{"cwe": 1}, {"cwe": 2}]
        result = server._merge_inline_suppressions(summary, [], inline)
        assert summary["suppressed"] == 2
        assert summary["active"] == 1
        assert summary["by_inline"] == 2
        assert result == inline

    def test_empty_inline_is_noop(self):
        """#15a: empty inline_suppressed leaves summary + suppressed unchanged."""
        summary = {"total": 1, "active": 1, "suppressed": 0, "by_directive": {}}
        existing = [{"cwe": 798}]
        result = server._merge_inline_suppressions(summary, existing, [])
        assert summary == {"total": 1, "active": 1, "suppressed": 0, "by_directive": {}}
        assert "by_inline" not in summary
        assert result == existing


class TestFormatCriticalWarning:
    """_format_critical_warning must name the actual suppression source(s).

    After _merge_inline_suppressions, the suppressed list can mix .armisignore
    and inline armis:ignore findings; the warning was hard-coded to ".armisignore"
    (PR #20 review). The source is derived per-finding from _suppression_source.
    """

    def test_armisignore_source(self):
        warning = server._format_critical_warning(
            [{"cwe": 798, "_suppression_source": "armisignore"}]
        )
        assert "suppressed by .armisignore" in warning
        assert "armis:ignore inline" not in warning
        assert "CWE-798" in warning
        assert "approve_findings is still required" in warning

    def test_inline_source(self):
        warning = server._format_critical_warning([{"cwe": 78, "_suppression_source": "inline"}])
        assert "suppressed by armis:ignore inline" in warning
        assert ".armisignore" not in warning

    def test_mixed_sources(self):
        warning = server._format_critical_warning(
            [
                {"cwe": 798, "_suppression_source": "armisignore"},
                {"cwe": 78, "_suppression_source": "inline"},
            ]
        )
        assert ".armisignore / armis:ignore inline" in warning
        assert "2 CRITICAL finding(s)" in warning
        assert "CWE-798" in warning and "CWE-78" in warning

    def test_missing_source_defaults_to_armisignore(self):
        """A finding with no _suppression_source falls back to .armisignore."""
        warning = server._format_critical_warning([{"cwe": 89}])
        assert "suppressed by .armisignore" in warning
