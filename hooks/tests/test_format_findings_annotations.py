"""Tests for source/sink annotations in format_findings()."""

import os
import sys

_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from unittest.mock import MagicMock

sys.modules.setdefault("mcp", MagicMock())
sys.modules.setdefault("mcp.server", MagicMock())
sys.modules.setdefault("mcp.server.fastmcp", MagicMock())
sys.modules.setdefault("mcp.server.fastmcp.exceptions", MagicMock())

from scanner_core import format_findings


class FakeTaintEntry:
    def __init__(self, function_name, kind):
        self.function_name = function_name
        self.kind = kind
        self.file_path = "/tmp/test.py"
        self.line = 1


class TestFormatFindingsAnnotations:
    def test_taint_map_match_adds_context_line(self):
        findings = [
            {
                "severity": "HIGH",
                "cwe": 89,
                "line": 10,
                "explanation": "SQL injection via cursor.execute with unsanitized input",
                "tainted_function_references": ["execute"],
            }
        ]
        taint_map = [FakeTaintEntry("execute", "sink")]
        result = format_findings(findings, "app.py", taint_map=taint_map)
        assert "context:" in result
        assert "execute [SINK]" in result

    def test_no_match_no_context_line(self):
        findings = [
            {
                "severity": "MEDIUM",
                "cwe": 79,
                "line": 5,
                "explanation": "XSS vulnerability in template rendering",
                "tainted_function_references": [],
            }
        ]
        taint_map = [FakeTaintEntry("execute", "sink")]
        result = format_findings(findings, "app.py", taint_map=taint_map)
        assert "context:" not in result

    def test_taint_map_none_unchanged(self):
        findings = [
            {
                "severity": "LOW",
                "cwe": 200,
                "line": 1,
                "explanation": "Information disclosure",
                "tainted_function_references": [],
            }
        ]
        result = format_findings(findings, "app.py", taint_map=None)
        assert "context:" not in result
        assert "Information disclosure" in result

    def test_multiple_matches_limited_to_three(self):
        findings = [
            {
                "severity": "HIGH",
                "cwe": 78,
                "line": 1,
                "explanation": "Uses run and exec and eval and system and popen",
                "tainted_function_references": [],
            }
        ]
        taint_map = [
            FakeTaintEntry("run", "sink"),
            FakeTaintEntry("exec", "sink"),
            FakeTaintEntry("eval", "sink"),
            FakeTaintEntry("system", "sink"),
            FakeTaintEntry("popen", "sink"),
        ]
        result = format_findings(findings, "app.py", taint_map=taint_map)
        context_line = [line for line in result.splitlines() if "context:" in line]
        assert len(context_line) == 1
        # At most 3 annotations
        annotations = context_line[0].split("context:")[1]
        assert annotations.count("[SINK]") <= 3

    def test_source_annotation(self):
        findings = [
            {
                "severity": "HIGH",
                "cwe": 89,
                "line": 5,
                "explanation": "User input from request.form passed to query",
                "tainted_function_references": ["request.form"],
            }
        ]
        taint_map = [FakeTaintEntry("request.form", "source")]
        result = format_findings(findings, "app.py", taint_map=taint_map)
        assert "request.form [SOURCE]" in result

    def test_backward_compat_no_taint_map(self):
        findings = [
            {
                "severity": "HIGH",
                "cwe": 89,
                "line": 10,
                "explanation": "SQL injection",
            }
        ]
        result_without = format_findings(findings, "app.py")
        result_with_none = format_findings(findings, "app.py", taint_map=None)
        assert result_without == result_with_none
