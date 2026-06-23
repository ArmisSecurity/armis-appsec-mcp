"""Tests for scanner_core.py — parse_findings, format_findings, URL validation, API call."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Add plugin dir to path so we can import scanner_core
_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from scanner_core import (
    build_diff_line_map,
    changed_lines_for_file,
    format_findings,
    parse_findings,
)


# ---------------------------------------------------------------------------
# parse_findings
# ---------------------------------------------------------------------------
class TestParseFindings:
    def test_valid_json_block(self):
        raw = (
            '```json\n[{"cwe": 89, "severity": "HIGH",'
            ' "line": 10, "explanation": "SQL injection"}]\n```'
        )
        result = parse_findings(raw)
        assert len(result) == 1
        assert result[0]["cwe"] == 89
        assert result[0]["severity"] == "HIGH"

    def test_multiple_findings(self):
        raw = (
            '```json\n[{"cwe": 89, "severity": "HIGH", "line": 10, "explanation": "SQLi"},'
            ' {"cwe": 79, "severity": "MEDIUM", "line": 20, "explanation": "XSS"}]\n```'
        )
        result = parse_findings(raw)
        assert len(result) == 2

    def test_no_json_block(self):
        raw = "No vulnerabilities found in this code."
        result = parse_findings(raw)
        assert result == []

    def test_malformed_json(self):
        raw = "```json\n{broken json\n```"
        result = parse_findings(raw)
        assert result == []

    def test_empty_findings_list(self):
        raw = "```json\n[]\n```"
        result = parse_findings(raw)
        assert result == []

    def test_filters_cwe_zero(self):
        raw = (
            '```json\n[{"cwe": 0, "severity": "INFO", "line": 1, "explanation": "no issue"},'
            ' {"cwe": 89, "severity": "HIGH", "line": 5, "explanation": "real"}]\n```'
        )
        result = parse_findings(raw)
        assert len(result) == 1
        assert result[0]["cwe"] == 89

    def test_filters_cwe_none(self):
        raw = (
            '```json\n[{"cwe": null, "severity": "INFO", "line": 1, "explanation": "no cwe"}]\n```'
        )
        result = parse_findings(raw)
        assert result == []

    def test_surrounding_text(self):
        raw = (
            'Here is the analysis:\n\n```json\n[{"cwe": 79, "severity": "HIGH",'
            ' "line": 3, "explanation": "XSS"}]\n```\n\nPlease fix these issues.'
        )
        result = parse_findings(raw)
        assert len(result) == 1
        assert result[0]["cwe"] == 79


# ---------------------------------------------------------------------------
# format_findings
# ---------------------------------------------------------------------------
class TestFormatFindings:
    def test_no_findings(self):
        result = format_findings([], "app.py")
        assert result == "SCAN app.py: clean, no findings."

    def test_single_finding(self):
        findings = [{"cwe": 89, "severity": "HIGH", "line": 10, "explanation": "SQL injection"}]
        result = format_findings(findings, "app.py")
        assert "SCAN app.py: 1 finding(s)" in result
        assert "HIGH CWE-89 L10: SQL injection" in result

    def test_severity_sorting(self):
        findings = [
            {"cwe": 79, "severity": "LOW", "line": 20, "explanation": "minor"},
            {"cwe": 89, "severity": "CRITICAL", "line": 10, "explanation": "critical"},
            {"cwe": 22, "severity": "HIGH", "line": 15, "explanation": "important"},
        ]
        result = format_findings(findings, "app.py")
        lines = result.split("\n")
        # CRITICAL should come before HIGH, which comes before LOW
        assert "CRITICAL" in lines[1]
        assert "HIGH" in lines[2]
        assert "LOW" in lines[3]

    def test_has_secret_flag(self):
        findings = [
            {
                "cwe": 798,
                "severity": "CRITICAL",
                "line": 5,
                "explanation": "hardcoded secret",
                "has_secret": True,
            }
        ]
        result = format_findings(findings, "secrets.py")
        assert "[SECRET]" in result

    def test_tainted_references(self):
        findings = [
            {
                "cwe": 89,
                "severity": "HIGH",
                "line": 10,
                "explanation": "SQLi",
                "tainted_function_references": ["get_user_input", "build_query"],
            }
        ]
        result = format_findings(findings, "db.py")
        assert "tainted: get_user_input, build_query" in result

    def test_no_tainted_references(self):
        findings = [
            {
                "cwe": 89,
                "severity": "HIGH",
                "line": 10,
                "explanation": "SQLi",
                "tainted_function_references": [],
            }
        ]
        result = format_findings(findings, "db.py")
        assert "tainted" not in result

    def test_missing_fields_use_defaults(self):
        findings = [{"cwe": 89}]
        result = format_findings(findings, "app.py")
        assert "UNKNOWN CWE-89 L?" in result

    def test_finding_with_file_path(self):
        findings = [{"cwe": 89, "severity": "HIGH", "line": 10, "explanation": "SQL injection"}]
        result = format_findings(findings, "app.py", file_path="/src/app.py")
        assert "/src/app.py:10" in result
        assert "L10" not in result

    def test_finding_with_line_map(self):
        findings = [{"cwe": 89, "severity": "HIGH", "line": 5, "explanation": "SQL injection"}]
        line_map = {5: ("src/db.py", 42)}
        result = format_findings(findings, "staged changes", line_map=line_map)
        assert "src/db.py:42" in result
        assert "L5" not in result

    def test_finding_line_map_miss(self):
        findings = [{"cwe": 89, "severity": "HIGH", "line": 99, "explanation": "SQL injection"}]
        line_map = {5: ("src/db.py", 42)}
        result = format_findings(findings, "staged changes", line_map=line_map)
        assert "L99" in result

    def test_line_map_takes_precedence_over_file_path(self):
        findings = [{"cwe": 89, "severity": "HIGH", "line": 5, "explanation": "SQL injection"}]
        line_map = {5: ("src/db.py", 42)}
        result = format_findings(
            findings, "staged changes", file_path="/other.py", line_map=line_map
        )
        assert "src/db.py:42" in result
        assert "/other.py" not in result

    def test_source_line_fallback_when_blob_miss(self):
        """LLM returns source-relative line numbers, not blob positions."""
        findings = [{"cwe": 770, "severity": "HIGH", "line": 42, "explanation": "unbounded"}]
        # blob key 99 maps to src/db.py:42 — finding line 42 is NOT a blob key,
        # but 42 IS a known source line, so fallback should resolve it.
        line_map = {99: ("src/db.py", 42)}
        result = format_findings(findings, "unstaged changes", line_map=line_map)
        assert "src/db.py:42" in result
        assert "L42" not in result

    def test_source_line_fallback_ambiguous(self):
        """If the same source line appears in multiple files, fall back to L{num}."""
        findings = [{"cwe": 770, "severity": "HIGH", "line": 10, "explanation": "unbounded"}]
        line_map = {50: ("a.py", 10), 80: ("b.py", 10)}
        result = format_findings(findings, "unstaged changes", line_map=line_map)
        assert "L10" in result

    def test_string_line_number_coercion(self):
        """Line numbers that come back as strings should still match line_map."""
        findings = [{"cwe": 89, "severity": "HIGH", "line": "5", "explanation": "SQLi"}]
        line_map = {5: ("src/db.py", 42)}
        result = format_findings(findings, "staged changes", line_map=line_map)
        assert "src/db.py:42" in result

    def test_cwe_name_included(self):
        findings = [
            {
                "cwe": 89,
                "cwe_name": "SQL Injection",
                "severity": "HIGH",
                "line": 10,
                "explanation": "SQLi",
            }
        ]
        result = format_findings(findings, "app.py")
        assert "(SQL Injection)" in result

    def test_cwe_name_empty_omitted(self):
        findings = [
            {
                "cwe": 89,
                "cwe_name": "",
                "severity": "HIGH",
                "line": 10,
                "explanation": "SQLi",
            }
        ]
        result = format_findings(findings, "app.py")
        assert "()" not in result
        assert "CWE-89 L10" in result

    def test_header_with_changed_files(self):
        result = format_findings([], "staged changes", changed_files=["a.py", "b.py"])
        assert "(2 file(s))" in result

    def test_header_with_findings_and_changed_files(self):
        findings = [{"cwe": 89, "severity": "HIGH", "line": 10, "explanation": "SQLi"}]
        result = format_findings(findings, "staged changes", changed_files=["a.py", "b.py"])
        assert "SCAN staged changes (2 file(s)): 1 finding(s)" in result


# ---------------------------------------------------------------------------
# build_diff_line_map
# ---------------------------------------------------------------------------
class TestBuildDiffLineMap:
    def test_simple_single_file(self):
        diff = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,3 +1,4 @@\n"
            " line1\n"
            "+added\n"
            " line3\n"
            " line4\n"
        )
        line_map, changed_files = build_diff_line_map(diff)
        assert changed_files == ["app.py"]
        # Line 5 in blob = " line1" → app.py:1
        assert line_map[5] == ("app.py", 1)
        # Line 6 in blob = "+added" → app.py:2
        assert line_map[6] == ("app.py", 2)
        # Line 7 in blob = " line3" → app.py:3
        assert line_map[7] == ("app.py", 3)

    def test_multi_file(self):
        diff = (
            "diff --git a/a.py b/a.py\n"
            "--- a/a.py\n"
            "+++ b/a.py\n"
            "@@ -1,2 +1,3 @@\n"
            " existing\n"
            "+new_in_a\n"
            " end\n"
            "diff --git a/b.py b/b.py\n"
            "--- a/b.py\n"
            "+++ b/b.py\n"
            "@@ -10,2 +10,3 @@\n"
            " ctx\n"
            "+new_in_b\n"
            " end\n"
        )
        line_map, changed_files = build_diff_line_map(diff)
        assert changed_files == ["a.py", "b.py"]
        # "+new_in_a" is blob line 6 → a.py:2
        assert line_map[6] == ("a.py", 2)
        # " ctx" is blob line 12 → b.py:10, "+new_in_b" is blob line 13 → b.py:11
        assert line_map[12] == ("b.py", 10)
        assert line_map[13] == ("b.py", 11)

    def test_removed_lines_not_mapped(self):
        diff = (
            "diff --git a/x.py b/x.py\n"
            "--- a/x.py\n"
            "+++ b/x.py\n"
            "@@ -1,3 +1,2 @@\n"
            " keep\n"
            "-removed\n"
            " also_keep\n"
        )
        line_map, _ = build_diff_line_map(diff)
        # "-removed" is blob line 6 — should NOT be in map
        assert 6 not in line_map
        # " keep" is blob line 5 → x.py:1
        assert line_map[5] == ("x.py", 1)
        # " also_keep" is blob line 7 → x.py:2 (not 3, because removed line doesn't count)
        assert line_map[7] == ("x.py", 2)

    def test_multiple_hunks(self):
        diff = (
            "diff --git a/f.py b/f.py\n"
            "--- a/f.py\n"
            "+++ b/f.py\n"
            "@@ -1,2 +1,3 @@\n"
            " first\n"
            "+added1\n"
            " second\n"
            "@@ -50,2 +51,3 @@\n"
            " fifty\n"
            "+added2\n"
            " fiftyone\n"
        )
        line_map, changed_files = build_diff_line_map(diff)
        assert changed_files == ["f.py"]
        # "+added1" blob line 6 → f.py:2
        assert line_map[6] == ("f.py", 2)
        # After second hunk header, " fifty" blob line 9 → f.py:51
        assert line_map[9] == ("f.py", 51)
        # "+added2" blob line 10 → f.py:52
        assert line_map[10] == ("f.py", 52)

    def test_empty_diff(self):
        line_map, changed_files = build_diff_line_map("")
        assert line_map == {}
        assert changed_files == []

    def test_changed_files_ordering(self):
        diff = (
            "diff --git a/z.py b/z.py\n"
            "+++ b/z.py\n"
            "@@ -1 +1,2 @@\n"
            "+a\n"
            "diff --git a/a.py b/a.py\n"
            "+++ b/a.py\n"
            "@@ -1 +1,2 @@\n"
            "+b\n"
        )
        _, changed_files = build_diff_line_map(diff)
        assert changed_files == ["z.py", "a.py"]  # order of appearance, not sorted


# ---------------------------------------------------------------------------
# changed_lines_for_file
# ---------------------------------------------------------------------------
class TestChangedLinesForFile:
    def test_added_and_context_lines(self):
        diff = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,3 +1,4 @@\n"
            " line1\n"
            "+added\n"
            " line3\n"
            " line4\n"
        )
        # All four lines (context + added) are in scope: 1, 2, 3, 4
        assert changed_lines_for_file(diff, "app.py") == {1, 2, 3, 4}

    def test_only_deletions(self):
        diff = (
            "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1,2 +1,1 @@\n kept\n-removed\n"
        )
        # File is in the diff; the deleted line doesn't count, but the context
        # line ("kept") at source line 1 is still in scope.
        assert changed_lines_for_file(diff, "x.py") == {1}

    def test_file_not_in_diff_returns_none(self):
        diff = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1,2 @@\n+x\n"
        assert changed_lines_for_file(diff, "b.py") is None

    def test_multi_file_only_requested_returned(self):
        diff = (
            "diff --git a/a.py b/a.py\n"
            "--- a/a.py\n"
            "+++ b/a.py\n"
            "@@ -1,2 +1,3 @@\n"
            " ctxA\n"
            "+addedA\n"
            " endA\n"
            "diff --git a/b.py b/b.py\n"
            "--- a/b.py\n"
            "+++ b/b.py\n"
            "@@ -10,2 +10,3 @@\n"
            " ctxB\n"
            "+addedB\n"
            " endB\n"
        )
        assert changed_lines_for_file(diff, "a.py") == {1, 2, 3}
        assert changed_lines_for_file(diff, "b.py") == {10, 11, 12}

    def test_empty_diff_returns_none(self):
        assert changed_lines_for_file("", "anything.py") is None


# ---------------------------------------------------------------------------
# format_findings: out_of_scope_count
# ---------------------------------------------------------------------------
class TestFormatFindingsOutOfScope:
    def test_zero_out_of_scope_no_suffix(self):
        result = format_findings([], "app.py", out_of_scope_count=0)
        assert result == "SCAN app.py: clean, no findings."

    def test_no_findings_with_out_of_scope(self):
        result = format_findings([], "app.py", out_of_scope_count=3)
        assert "SCAN app.py: 0 finding(s)" in result
        assert "(3 outside diff scope)" in result

    def test_findings_with_out_of_scope_in_header(self):
        findings = [{"severity": "HIGH", "cwe": 89, "line": 5, "explanation": "x"}]
        result = format_findings(findings, "app.py", out_of_scope_count=2)
        # Header should show count of in-scope findings AND the out-of-scope tail
        assert "1 finding(s)" in result.splitlines()[0]
        assert "(2 outside diff scope)" in result.splitlines()[0]

    def test_out_of_scope_with_suppression(self):
        findings = [{"severity": "HIGH", "cwe": 89, "line": 5, "explanation": "x"}]
        result = format_findings(
            findings,
            "app.py",
            suppression_summary={"suppressed": 1, "by_directive": {"cwe:89": 1}, "by_inline": 0},
            out_of_scope_count=4,
        )
        # Both the (active, suppressed) clause and the out-of-scope clause should appear
        assert "1 active, 1 suppressed" in result
        assert "(4 outside diff scope)" in result.splitlines()[0]


# ---------------------------------------------------------------------------
# URL validation (call_appsec_api checks)
# ---------------------------------------------------------------------------
class TestURLValidation:
    def test_http_non_localhost_raises(self):
        """Non-HTTPS, non-localhost URL raises RuntimeError."""
        import scanner_core

        original_url = scanner_core.APPSEC_API_URL
        try:
            scanner_core.APPSEC_API_URL = "http://evil.com/api/v1"
            with patch("scanner_core.get_auth_header", return_value="Bearer fake"):
                with pytest.raises(RuntimeError, match="HTTPS"):
                    scanner_core.call_appsec_api("code")
        finally:
            scanner_core.APPSEC_API_URL = original_url

    def test_http_localhost_allowed(self):
        """HTTP with localhost hostname does not raise HTTPS error.

        It will fail on connection since there's no server, but it should
        NOT raise the HTTPS validation error.
        """
        import scanner_core

        original_url = scanner_core.APPSEC_API_URL
        try:
            scanner_core.APPSEC_API_URL = "http://localhost:8001/api/v1"
            with patch("scanner_core.get_auth_header", return_value="Bearer fake"):
                # Should raise a connection error, NOT a RuntimeError about HTTPS
                with pytest.raises(Exception) as exc_info:
                    scanner_core.call_appsec_api("code")
                assert "HTTPS" not in str(exc_info.value)
        finally:
            scanner_core.APPSEC_API_URL = original_url

    def test_http_evil_localhost_rejected(self):
        """S-4: http://evil-localhost.com is NOT treated as localhost."""
        import scanner_core

        original_url = scanner_core.APPSEC_API_URL
        try:
            scanner_core.APPSEC_API_URL = "http://evil-localhost.com/api/v1"
            with patch("scanner_core.get_auth_header", return_value="Bearer fake"):
                with pytest.raises(RuntimeError, match="HTTPS"):
                    scanner_core.call_appsec_api("code")
        finally:
            scanner_core.APPSEC_API_URL = original_url


# ---------------------------------------------------------------------------
# call_appsec_api happy path
# ---------------------------------------------------------------------------
class TestCallAppsecApiHappyPath:
    def test_sends_correct_payload_and_returns_raw_response(self):
        """Verify: URL, auth header, timeout, payload, and return value."""
        import scanner_core

        original_url = scanner_core.APPSEC_API_URL
        try:
            scanner_core.APPSEC_API_URL = "https://moose.armis.com/api/v1"

            mock_response = MagicMock()
            mock_response.json.return_value = {"raw_response": "```json\n[]\n```"}
            mock_response.raise_for_status = MagicMock()

            with patch("scanner_core.get_auth_header", return_value="Bearer test-token"):
                with patch("scanner_core.httpx.post", return_value=mock_response) as mock_post:
                    result = scanner_core.call_appsec_api("print('hello')")

            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args.kwargs["json"] == {
                "code": "print('hello')",
                "mode": "fast",
            }
            assert call_args.kwargs["headers"] == {"Authorization": "Bearer test-token"}
            assert call_args.kwargs["timeout"] == 120.0
            assert "scan/fast" in call_args.args[0]
            assert result == "```json\n[]\n```"
        finally:
            scanner_core.APPSEC_API_URL = original_url
