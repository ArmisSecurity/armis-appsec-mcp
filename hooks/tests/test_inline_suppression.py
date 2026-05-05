"""Unit tests for inline armis:ignore comment suppression (ADR-0008 Category C + D)."""

from suppression import (
    InlineDirective,
    _extract_comment_text,
    _finding_matches_inline,
    _get_comment_prefixes,
    _parse_inline_directive,
    apply_inline_suppressions,
)

# ---------------------------------------------------------------------------
# Category C: Inline directive parsing
# ---------------------------------------------------------------------------


class TestParseInlineDirective:
    """Test _parse_inline_directive with various inputs."""

    def test_bare_directive(self):
        d = _parse_inline_directive("armis:ignore")
        assert d is not None
        assert d.is_bare is True

    def test_bare_case_insensitive(self):
        d = _parse_inline_directive("ARMIS:IGNORE")
        assert d is not None
        assert d.is_bare is True

    def test_cwe_only(self):
        d = _parse_inline_directive("armis:ignore cwe:798")
        assert d is not None
        assert d.cwe == 798
        assert d.is_bare is False

    def test_severity_only(self):
        d = _parse_inline_directive("armis:ignore severity:HIGH")
        assert d is not None
        assert d.severity == "HIGH"
        assert d.is_bare is False

    def test_category_only(self):
        d = _parse_inline_directive("armis:ignore category:secrets")
        assert d is not None
        assert d.category == "secrets"
        assert d.is_bare is False

    def test_rule_only_not_bare(self):
        """rule-only directive is NOT bare — it matches nothing in MCP context (D1)."""
        d = _parse_inline_directive("armis:ignore rule:CKV_AWS_18")
        assert d is not None
        assert d.is_bare is False
        assert d.cwe is None
        assert d.severity is None
        assert d.category is None

    def test_rule_plus_cwe(self):
        """rule: is consumed but ignored; cwe: is enforced (D1)."""
        d = _parse_inline_directive("armis:ignore rule:CKV_AWS_18 cwe:798")
        assert d is not None
        assert d.cwe == 798
        assert d.is_bare is False

    def test_multiple_params_any_order(self):
        d = _parse_inline_directive("armis:ignore cwe:79 category:sast severity:HIGH")
        assert d is not None
        assert d.cwe == 79
        assert d.category == "sast"
        assert d.severity == "HIGH"

    def test_reason_captures_rest(self):
        d = _parse_inline_directive("armis:ignore cwe:798 reason: Not hardcoded, env var")
        assert d is not None
        assert d.cwe == 798
        assert d.reason == "Not hardcoded, env var"

    def test_invalid_cwe_ignored(self):
        """cwe:abc is silently ignored — directive becomes bare (D6)."""
        d = _parse_inline_directive("armis:ignore cwe:abc")
        assert d is not None
        assert d.is_bare is True
        assert d.cwe is None

    def test_duplicate_key_last_wins(self):
        """Duplicate keys: last-wins behavior (D6)."""
        d = _parse_inline_directive("armis:ignore cwe:79 cwe:89")
        assert d is not None
        assert d.cwe == 89

    def test_no_armis_ignore_returns_none(self):
        d = _parse_inline_directive("just some text")
        assert d is None


# ---------------------------------------------------------------------------
# Category C: Comment syntax detection
# ---------------------------------------------------------------------------


class TestGetCommentPrefixes:
    def test_python(self):
        assert _get_comment_prefixes("/path/to/file.py") == ["#"]

    def test_javascript(self):
        assert _get_comment_prefixes("/path/to/file.js") == ["//"]

    def test_typescript(self):
        assert _get_comment_prefixes("/path/to/file.tsx") == ["//"]

    def test_sql(self):
        assert _get_comment_prefixes("/path/to/query.sql") == ["--"]

    def test_html(self):
        assert _get_comment_prefixes("/path/to/index.html") == ["<!--"]

    def test_css(self):
        assert _get_comment_prefixes("/path/to/style.css") == ["/*"]

    def test_ini(self):
        assert _get_comment_prefixes("/path/to/config.ini") == [";"]

    def test_php_both(self):
        prefixes = _get_comment_prefixes("/path/to/file.php")
        assert "//" in prefixes
        assert "#" in prefixes

    def test_unknown_extension_fallback(self):
        prefixes = _get_comment_prefixes("/path/to/file.xyz")
        assert "#" in prefixes
        assert "//" in prefixes


class TestExtractCommentText:
    def test_hash_comment(self):
        result = _extract_comment_text("x = 1  # armis:ignore cwe:798", ["#"])
        assert result == "armis:ignore cwe:798"

    def test_double_slash(self):
        result = _extract_comment_text('String token = "x";  // armis:ignore', ["//"])
        assert result == "armis:ignore"

    def test_double_dash(self):
        result = _extract_comment_text("SELECT * FROM t;  -- armis:ignore", ["--"])
        assert result == "armis:ignore"

    def test_semicolon(self):
        result = _extract_comment_text("; armis:ignore cwe:798", [";"])
        assert result == "armis:ignore cwe:798"

    def test_html_block(self):
        result = _extract_comment_text("<!-- armis:ignore category:sast -->", ["<!--"])
        assert result == "armis:ignore category:sast"

    def test_css_block(self):
        result = _extract_comment_text("/* armis:ignore severity:LOW */", ["/*"])
        assert result == "armis:ignore severity:LOW"

    def test_no_comment_returns_none(self):
        result = _extract_comment_text("x = 1", ["#"])
        assert result is None

    def test_html_unclosed_returns_none(self):
        result = _extract_comment_text("<!-- armis:ignore", ["<!--"])
        assert result is None

    def test_css_unclosed_returns_none(self):
        result = _extract_comment_text("/* armis:ignore", ["/*"])
        assert result is None


# ---------------------------------------------------------------------------
# Category C: Finding matching (AND logic)
# ---------------------------------------------------------------------------


class TestFindingMatchesInline:
    def test_bare_matches_everything(self):
        finding = {"cwe": 798, "severity": "HIGH", "has_secret": True}
        directive = InlineDirective(is_bare=True)
        assert _finding_matches_inline(finding, directive) is True

    def test_rule_only_matches_nothing(self):
        """Rule-only directive (D1): not bare, all fields None → no match."""
        finding = {"cwe": 798, "severity": "HIGH", "has_secret": True}
        directive = InlineDirective()  # not bare, all None
        assert _finding_matches_inline(finding, directive) is False

    def test_cwe_match(self):
        finding = {"cwe": 798, "severity": "HIGH", "has_secret": True}
        directive = InlineDirective(cwe=798)
        assert _finding_matches_inline(finding, directive) is True

    def test_cwe_no_match(self):
        finding = {"cwe": 79, "severity": "HIGH", "has_secret": False}
        directive = InlineDirective(cwe=798)
        assert _finding_matches_inline(finding, directive) is False

    def test_severity_match_case_insensitive(self):
        finding = {"cwe": 79, "severity": "high", "has_secret": False}
        directive = InlineDirective(severity="HIGH")
        assert _finding_matches_inline(finding, directive) is True

    def test_category_secrets_match(self):
        finding = {"cwe": 798, "severity": "HIGH", "has_secret": True}
        directive = InlineDirective(category="secrets")
        assert _finding_matches_inline(finding, directive) is True

    def test_category_sast_match(self):
        finding = {"cwe": 79, "severity": "HIGH", "has_secret": False}
        directive = InlineDirective(category="sast")
        assert _finding_matches_inline(finding, directive) is True

    def test_category_sast_no_match_on_secret(self):
        finding = {"cwe": 798, "severity": "HIGH", "has_secret": True}
        directive = InlineDirective(category="sast")
        assert _finding_matches_inline(finding, directive) is False

    def test_and_logic_both_match(self):
        finding = {"cwe": 79, "severity": "HIGH", "has_secret": False}
        directive = InlineDirective(category="sast", cwe=79)
        assert _finding_matches_inline(finding, directive) is True

    def test_and_logic_partial_no_match(self):
        """category matches but cwe doesn't → no match (AND logic)."""
        finding = {"cwe": 79, "severity": "HIGH", "has_secret": False}
        directive = InlineDirective(category="sast", cwe=89)
        assert _finding_matches_inline(finding, directive) is False


# ---------------------------------------------------------------------------
# Category C + D: apply_inline_suppressions (integration)
# ---------------------------------------------------------------------------


class TestApplyInlineSuppressions:
    def test_bare_suppresses_all_same_line(self, tmp_path):
        source = tmp_path / "app.py"
        source.write_text("password = 'secret'  # armis:ignore\n")
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 1}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(active) == 0
        assert len(suppressed) == 1
        assert suppressed[0]["_suppression_source"] == "inline"

    def test_line_above(self, tmp_path):
        source = tmp_path / "app.py"
        source.write_text("# armis:ignore cwe:798\npassword = 'secret'\n")
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 2}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(active) == 0
        assert len(suppressed) == 1

    def test_cwe_match(self, tmp_path):
        source = tmp_path / "app.py"
        source.write_text("x = get_pass()  # armis:ignore cwe:798\n")
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 1}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(suppressed) == 1

    def test_cwe_no_match(self, tmp_path):
        source = tmp_path / "app.py"
        source.write_text("x = get_pass()  # armis:ignore cwe:798\n")
        findings = [{"cwe": 79, "severity": "HIGH", "has_secret": False, "line": 1}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(active) == 1
        assert len(suppressed) == 0

    def test_and_logic_both_required(self, tmp_path):
        source = tmp_path / "app.py"
        source.write_text("x = y  # armis:ignore category:sast cwe:89\n")
        finding_89 = {"cwe": 89, "severity": "HIGH", "has_secret": False, "line": 1}
        finding_79 = {"cwe": 79, "severity": "HIGH", "has_secret": False, "line": 1}
        active, suppressed = apply_inline_suppressions([finding_89], str(source))
        assert len(suppressed) == 1
        active, suppressed = apply_inline_suppressions([finding_79], str(source))
        assert len(suppressed) == 0

    def test_rule_only_no_match(self, tmp_path):
        """rule-only inline directive matches nothing in MCP (D1)."""
        source = tmp_path / "app.py"
        source.write_text("x = y  # armis:ignore rule:CKV_AWS_18\n")
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 1}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(active) == 1
        assert len(suppressed) == 0

    def test_rule_plus_cwe_enforces_cwe(self, tmp_path):
        source = tmp_path / "app.py"
        source.write_text("x = y  # armis:ignore rule:CKV_AWS_18 cwe:798\n")
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 1}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(suppressed) == 1

    def test_js_double_slash(self, tmp_path):
        source = tmp_path / "app.js"
        source.write_text('const token = "x";  // armis:ignore cwe:798\n')
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 1}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(suppressed) == 1

    def test_sql_double_dash(self, tmp_path):
        source = tmp_path / "query.sql"
        source.write_text("SELECT * FROM t;  -- armis:ignore severity:HIGH\n")
        findings = [{"cwe": 89, "severity": "HIGH", "has_secret": False, "line": 1}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(suppressed) == 1

    def test_html_block_comment(self, tmp_path):
        source = tmp_path / "index.html"
        source.write_text("<!-- armis:ignore category:sast -->\n<div></div>\n")
        findings = [{"cwe": 79, "severity": "HIGH", "has_secret": False, "line": 2}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(suppressed) == 1

    def test_css_block_comment(self, tmp_path):
        source = tmp_path / "style.css"
        source.write_text("/* armis:ignore severity:LOW */\nbackground: url(data:);\n")
        findings = [{"cwe": 79, "severity": "LOW", "has_secret": False, "line": 2}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(suppressed) == 1

    def test_ini_semicolon(self, tmp_path):
        source = tmp_path / "config.ini"
        source.write_text("; armis:ignore cwe:798\napi_key = ${API_KEY}\n")
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 2}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(suppressed) == 1

    def test_source_lines_param_skips_read(self, tmp_path):
        """When source_lines is provided, file is not read from disk."""
        lines = ["password = 'x'  # armis:ignore\n"]
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 1}]
        active, suppressed = apply_inline_suppressions(
            findings, "/nonexistent/path.py", source_lines=lines
        )
        assert len(suppressed) == 1

    def test_no_comment_on_line(self, tmp_path):
        """Finding on a line with no comment stays active (D6 gap)."""
        source = tmp_path / "app.py"
        source.write_text("password = 'secret'\n")
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 1}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(active) == 1
        assert len(suppressed) == 0

    def test_suppression_metadata_annotated(self, tmp_path):
        """Suppressed findings carry _suppression_source and _suppressed_by (D3)."""
        source = tmp_path / "app.py"
        source.write_text("x = 1  # armis:ignore cwe:798\n")
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 1}]
        _, suppressed = apply_inline_suppressions(findings, str(source))
        assert suppressed[0]["_suppression_source"] == "inline"
        assert "armis:ignore" in suppressed[0]["_suppressed_by"]


# ---------------------------------------------------------------------------
# Category D: Edge cases (fail-open)
# ---------------------------------------------------------------------------


class TestInlineEdgeCases:
    def test_file_not_found_fail_open(self):
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 1}]
        active, suppressed = apply_inline_suppressions(findings, "/nonexistent/file.py")
        assert len(active) == 1
        assert len(suppressed) == 0

    def test_line_zero_skipped(self, tmp_path):
        source = tmp_path / "app.py"
        source.write_text("# armis:ignore\nx = 1\n")
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 0}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(active) == 1
        assert len(suppressed) == 0

    def test_negative_line_skipped(self, tmp_path):
        source = tmp_path / "app.py"
        source.write_text("# armis:ignore\nx = 1\n")
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": -1}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(active) == 1
        assert len(suppressed) == 0

    def test_line_beyond_eof(self, tmp_path):
        source = tmp_path / "app.py"
        source.write_text("x = 1\n")
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 999}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(active) == 1
        assert len(suppressed) == 0

    def test_binary_file_fail_open(self, tmp_path):
        source = tmp_path / "data.bin"
        source.write_bytes(b"\x00\x01\x02\x03" * 100)
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 1}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(active) == 1
        assert len(suppressed) == 0

    def test_no_valid_lines_early_return(self, tmp_path):
        """All findings have line=0 → nothing to check (D6 gap)."""
        source = tmp_path / "app.py"
        source.write_text("# armis:ignore\n")
        findings = [
            {"cwe": 798, "severity": "HIGH", "has_secret": True, "line": 0},
            {"cwe": 79, "severity": "MEDIUM", "has_secret": False, "line": 0},
        ]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(active) == 2
        assert len(suppressed) == 0

    def test_empty_findings_returns_empty(self, tmp_path):
        source = tmp_path / "app.py"
        source.write_text("# armis:ignore\n")
        active, suppressed = apply_inline_suppressions([], str(source))
        assert active == []
        assert suppressed == []

    def test_non_int_line_skipped(self, tmp_path):
        source = tmp_path / "app.py"
        source.write_text("x = 1  # armis:ignore\n")
        findings = [{"cwe": 798, "severity": "HIGH", "has_secret": True, "line": "bad"}]
        active, suppressed = apply_inline_suppressions(findings, str(source))
        assert len(active) == 1
        assert len(suppressed) == 0
