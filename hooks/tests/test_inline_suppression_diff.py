"""Unit tests for inline armis:ignore suppression on DIFF scans (PPSC-903).

These exercise ``apply_inline_suppressions_to_diff``, which matches inline
directives against the diff blob (findings carry blob line numbers, not source
lines). Diffs are run through the real ``build_diff_line_map`` so the blob->source
mapping is authentic; finding ``line`` values are located by substring to avoid
brittle hardcoded offsets.
"""

import os
import sys
import textwrap

# Add plugin dir to path so we can import scanner_core / suppression
_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from scanner_core import build_diff_line_map
from suppression import apply_inline_suppressions_to_diff


def _blob_line(diff_text: str, needle: str) -> int:
    """Return the 1-based blob line number of the line containing ``needle``."""
    for i, line in enumerate(diff_text.splitlines(), start=1):
        if needle in line:
            return i
    raise AssertionError(f"needle {needle!r} not found in diff")


def _run(diff_text: str, findings: list[dict]):
    line_map, _ = build_diff_line_map(diff_text)
    return apply_inline_suppressions_to_diff(findings, diff_text, line_map)


# ---------------------------------------------------------------------------
# Basic suppression on the finding's own line
# ---------------------------------------------------------------------------
class TestOwnLine:
    def test_bare_directive_on_added_line(self):
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            --- a/app.py
            +++ b/app.py
            @@ -0,0 +1,1 @@
            +password = "secret"  # armis:ignore
            """)
        line = _blob_line(diff, "password")
        findings = [{"cwe": 798, "severity": "HIGH", "line": line}]
        active, suppressed = _run(diff, findings)
        assert active == []
        assert len(suppressed) == 1
        assert suppressed[0]["_suppression_source"] == "inline"

    def test_cwe_specific_matches_and_misses(self):
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            --- a/app.py
            +++ b/app.py
            @@ -0,0 +1,1 @@
            +token = "x"  # armis:ignore cwe:798
            """)
        line = _blob_line(diff, "token")
        # Matching CWE -> suppressed.
        active, suppressed = _run(diff, [{"cwe": 798, "severity": "HIGH", "line": line}])
        assert suppressed and active == []
        # Non-matching CWE on the same line -> stays active (AND logic).
        active, suppressed = _run(diff, [{"cwe": 89, "severity": "HIGH", "line": line}])
        assert active and suppressed == []

    def test_suppressed_by_contains_comment_text(self):
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            +++ b/app.py
            @@ -0,0 +1,1 @@
            +token = "x"  # armis:ignore cwe:798
            """)
        line = _blob_line(diff, "token")
        _active, suppressed = _run(diff, [{"cwe": 798, "severity": "HIGH", "line": line}])
        assert "armis:ignore" in suppressed[0]["_suppressed_by"]
        assert suppressed[0]["_suppressed_by"] == "armis:ignore cwe:798"


# ---------------------------------------------------------------------------
# "Line above" via source coordinates (D3)
# ---------------------------------------------------------------------------
class TestLineAbove:
    def test_directive_on_content_line_above(self):
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            +++ b/app.py
            @@ -0,0 +1,2 @@
            +# armis:ignore cwe:798
            +password = "secret"
            """)
        line = _blob_line(diff, "password")
        active, suppressed = _run(diff, [{"cwe": 798, "severity": "HIGH", "line": line}])
        assert suppressed and active == []

    def test_removed_line_comment_above_does_not_suppress(self):
        # The removed line bears a directive but is deleted code -> must NOT suppress.
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            +++ b/app.py
            @@ -1,1 +1,1 @@
            -old = pw  # armis:ignore cwe:798
            +new = pw
            """)
        line = _blob_line(diff, "+new = pw")
        active, suppressed = _run(diff, [{"cwe": 798, "severity": "HIGH", "line": line}])
        assert active and suppressed == []

    def test_hunk_header_above_does_not_suppress(self):
        # Finding on the first added line of a hunk; nothing real above it.
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            +++ b/app.py
            @@ -5,3 +5,3 @@
            +vulnerable_code()
            """)
        line = _blob_line(diff, "vulnerable_code")
        active, suppressed = _run(diff, [{"cwe": 89, "severity": "HIGH", "line": line}])
        assert active and suppressed == []


# ---------------------------------------------------------------------------
# Multi-file diffs (per-file comment prefixes + isolation)
# ---------------------------------------------------------------------------
class TestMultiFile:
    def test_per_file_prefixes_and_isolation(self):
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            +++ b/app.py
            @@ -0,0 +1,1 @@
            +secret = "x"  # armis:ignore cwe:798
            diff --git a/app.js b/app.js
            +++ b/app.js
            @@ -0,0 +1,1 @@
            +const s = "y";  // armis:ignore cwe:89
            """)
        py_line = _blob_line(diff, "secret =")
        js_line = _blob_line(diff, "const s")

        # py '#' directive suppresses the py finding.
        active, suppressed = _run(diff, [{"cwe": 798, "severity": "HIGH", "line": py_line}])
        assert suppressed and active == []
        # js '//' directive suppresses the js finding (proves // prefix works).
        active, suppressed = _run(diff, [{"cwe": 89, "severity": "HIGH", "line": js_line}])
        assert suppressed and active == []
        # js directive (cwe:89) does NOT suppress a cwe:798 finding on the js line.
        active, suppressed = _run(diff, [{"cwe": 798, "severity": "HIGH", "line": js_line}])
        assert active and suppressed == []

    def test_cross_file_line_above_does_not_suppress(self):
        # File A's only line carries the directive; file B's finding is the same CWE.
        # Source-coordinate "line above" must never cross the file boundary.
        diff = textwrap.dedent("""\
            diff --git a/a.py b/a.py
            +++ b/a.py
            @@ -0,0 +1,1 @@
            +x = 1  # armis:ignore cwe:798
            diff --git a/b.py b/b.py
            +++ b/b.py
            @@ -0,0 +1,1 @@
            +secret = "y"
            """)
        b_line = _blob_line(diff, "secret =")
        active, suppressed = _run(diff, [{"cwe": 798, "severity": "HIGH", "line": b_line}])
        assert active and suppressed == []


# ---------------------------------------------------------------------------
# Block-comment languages
# ---------------------------------------------------------------------------
class TestBlockComments:
    def test_html_block_comment(self):
        diff = textwrap.dedent("""\
            diff --git a/page.html b/page.html
            +++ b/page.html
            @@ -0,0 +1,1 @@
            +<div>x</div> <!-- armis:ignore cwe:79 -->
            """)
        line = _blob_line(diff, "<div>")
        active, suppressed = _run(diff, [{"cwe": 79, "severity": "MEDIUM", "line": line}])
        assert suppressed and active == []

    def test_css_block_comment(self):
        diff = textwrap.dedent("""\
            diff --git a/s.css b/s.css
            +++ b/s.css
            @@ -0,0 +1,1 @@
            +a { color: red } /* armis:ignore cwe:79 */
            """)
        line = _blob_line(diff, "color: red")
        active, suppressed = _run(diff, [{"cwe": 79, "severity": "MEDIUM", "line": line}])
        assert suppressed and active == []


# ---------------------------------------------------------------------------
# Out-of-range / malformed line values
# ---------------------------------------------------------------------------
class TestOutOfRange:
    def _diff(self):
        return textwrap.dedent("""\
            diff --git a/app.py b/app.py
            +++ b/app.py
            @@ -0,0 +1,1 @@
            +token = "x"  # armis:ignore cwe:798
            """)

    def test_line_past_eof(self):
        active, suppressed = _run(self._diff(), [{"cwe": 798, "line": 9999}])
        assert active and suppressed == []

    def test_line_zero(self):
        active, suppressed = _run(self._diff(), [{"cwe": 798, "line": 0}])
        assert active and suppressed == []

    def test_line_negative(self):
        active, suppressed = _run(self._diff(), [{"cwe": 798, "line": -3}])
        assert active and suppressed == []

    def test_line_non_int(self):
        active, suppressed = _run(self._diff(), [{"cwe": 798, "line": "?"}])
        assert active and suppressed == []

    def test_line_missing(self):
        active, suppressed = _run(self._diff(), [{"cwe": 798}])
        assert active and suppressed == []

    def test_line_maps_to_metadata(self):
        # A blob line that exists but is a metadata line (the '+++ b/' header) is
        # not a line_map key -> never suppressed.
        diff = self._diff()
        meta_line = _blob_line(diff, "+++ b/app.py")
        active, suppressed = _run(diff, [{"cwe": 798, "line": meta_line}])
        assert active and suppressed == []


# ---------------------------------------------------------------------------
# Degenerate inputs
# ---------------------------------------------------------------------------
class TestDegenerate:
    def test_empty_findings(self):
        active, suppressed = _run("diff --git a/x b/x\n", [])
        assert active == []
        assert suppressed == []

    def test_empty_diff(self):
        findings = [{"cwe": 798, "line": 1}]
        active, suppressed = apply_inline_suppressions_to_diff(findings, "", {})
        assert active == findings
        assert suppressed == []

    def test_fail_open_on_bad_line_map(self):
        """A malformed line_map raises internally -> fail open, all findings active."""
        findings = [{"cwe": 798, "line": 1}]
        # line_map values must be (file, src) tuples; a bad shape triggers the
        # except branch, which must return findings unchanged (never lose them).
        active, suppressed = apply_inline_suppressions_to_diff(findings, "+x\n", {1: "not-a-tuple"})
        assert active == findings
        assert suppressed == []


# ---------------------------------------------------------------------------
# Directive param matching in the diff path (cwe is covered above; these cover
# the severity:/category: AND-branches and free-text reason: through the blob).
# ---------------------------------------------------------------------------
class TestDirectiveParamsInDiff:
    def test_severity_specific_matches_and_misses(self):
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            +++ b/app.py
            @@ -0,0 +1,1 @@
            +pw = "x"  # armis:ignore severity:HIGH
            """)
        line = _blob_line(diff, "pw =")
        # severity matches (case-insensitive) -> suppressed.
        _a, s = _run(diff, [{"cwe": 798, "severity": "HIGH", "line": line}])
        assert s and _a == []
        # different severity on the same line -> stays active (AND logic).
        a, s = _run(diff, [{"cwe": 798, "severity": "CRITICAL", "line": line}])
        assert a and s == []

    def test_category_specific_matches_and_misses(self):
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            +++ b/app.py
            @@ -0,0 +1,1 @@
            +k = "x"  # armis:ignore category:secrets
            """)
        line = _blob_line(diff, "k =")
        # has_secret=True -> category "secrets" -> matches.
        _a, s = _run(diff, [{"cwe": 798, "has_secret": True, "line": line}])
        assert s and _a == []
        # has_secret falsey -> category "sast" -> stays active.
        a, s = _run(diff, [{"cwe": 89, "has_secret": False, "line": line}])
        assert a and s == []

    def test_directive_with_reason_suppresses(self):
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            +++ b/app.py
            @@ -0,0 +1,1 @@
            +pw = "x"  # armis:ignore cwe:798 reason: legacy creds
            """)
        line = _blob_line(diff, "pw =")
        _a, s = _run(diff, [{"cwe": 798, "severity": "HIGH", "line": line}])
        assert s and "reason:" in s[0]["_suppressed_by"]


# ---------------------------------------------------------------------------
# Marker case-insensitivity and additional comment prefixes in the diff path.
# ---------------------------------------------------------------------------
class TestMarkerAndPrefixesInDiff:
    def test_marker_case_insensitive(self):
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            +++ b/app.py
            @@ -0,0 +1,1 @@
            +pw = "x"  # ARMIS:IGNORE cwe:798
            """)
        line = _blob_line(diff, "pw =")
        _a, s = _run(diff, [{"cwe": 798, "severity": "HIGH", "line": line}])
        assert s and s[0]["_suppression_source"] == "inline"

    def test_sql_dashdash_comment(self):
        diff = textwrap.dedent("""\
            diff --git a/q.sql b/q.sql
            +++ b/q.sql
            @@ -0,0 +1,1 @@
            +SELECT 1  -- armis:ignore cwe:89
            """)
        line = _blob_line(diff, "SELECT 1")
        _a, s = _run(diff, [{"cwe": 89, "severity": "HIGH", "line": line}])
        assert s and _a == []


# ---------------------------------------------------------------------------
# Context (space-prefixed) lines and bare directive on the line above.
# These exercise the [1:] marker-strip on a non-'+' line and the source-coord
# "line above" reverse lookup with a bare directive.
# ---------------------------------------------------------------------------
class TestContextAndBareLineAbove:
    def test_directive_on_context_line(self):
        # The directive lives on an unchanged context line; the finding is on it.
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            +++ b/app.py
            @@ -1,2 +1,2 @@
             password = "x"  # armis:ignore cwe:798
            +query = "y"
            """)
        line = _blob_line(diff, "password")
        _a, s = _run(diff, [{"cwe": 798, "severity": "HIGH", "line": line}])
        assert s and _a == []

    def test_bare_directive_line_above(self):
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            +++ b/app.py
            @@ -0,0 +1,2 @@
            +# armis:ignore
            +password = "secret"
            """)
        line = _blob_line(diff, "password")
        a, s = _run(diff, [{"cwe": 798, "severity": "HIGH", "line": line}])
        assert s and a == []


# ---------------------------------------------------------------------------
# String-literal directive bypass (PPSC-903 eng-review hardening).
# A marker inside a quoted string must NOT start a directive -- the finding on
# that line stays ACTIVE (fail-safe direction for a suppression parser).
# ---------------------------------------------------------------------------
class TestStringLiteralBypass:
    def test_marker_in_python_string_does_not_suppress(self):
        diff = textwrap.dedent("""\
            diff --git a/app.py b/app.py
            +++ b/app.py
            @@ -0,0 +1,1 @@
            +q = run("SELECT #armis:ignore cwe:89" + user)
            """)
        line = _blob_line(diff, "SELECT")
        a, s = _run(diff, [{"cwe": 89, "severity": "HIGH", "line": line}])
        assert a and s == []

    def test_marker_in_js_string_does_not_suppress(self):
        diff = textwrap.dedent("""\
            diff --git a/app.js b/app.js
            +++ b/app.js
            @@ -0,0 +1,1 @@
            +const x = "// armis:ignore cwe:79";
            """)
        line = _blob_line(diff, "const x")
        a, s = _run(diff, [{"cwe": 79, "severity": "HIGH", "line": line}])
        assert a and s == []

    def test_real_comment_after_string_still_suppresses(self):
        # A genuine comment that follows a string containing a '#' must still work.
        diff = textwrap.dedent("""\
            diff --git a/q.sql b/q.sql
            +++ b/q.sql
            @@ -0,0 +1,1 @@
            +SELECT '--x' FROM t  -- armis:ignore cwe:89
            """)
        line = _blob_line(diff, "SELECT")
        _a, s = _run(diff, [{"cwe": 89, "severity": "HIGH", "line": line}])
        assert s and _a == []

    def test_escaped_quote_does_not_end_string_early(self):
        # The escaped quote (\\") must not close the string, so the real trailing
        # comment is still found and suppression applies. Exercises the
        # backslash-escape branch of _find_comment_start.
        diff = textwrap.dedent("""\
            diff --git a/app.js b/app.js
            +++ b/app.js
            @@ -0,0 +1,1 @@
            +const s = "a\\" // not a comment";  // armis:ignore cwe:79
            """)
        line = _blob_line(diff, "const s")
        _a, s = _run(diff, [{"cwe": 79, "severity": "HIGH", "line": line}])
        assert s and _a == []


# ---------------------------------------------------------------------------
# Multi-CWE directives on the diff path (regression for PPSC-920: a
# `// armis:ignore cwe:78 cwe:77` directive above a Go sink line failed to clear
# a CWE-78 finding because the parser kept only the last CWE).
# ---------------------------------------------------------------------------
class TestMultiCweInDiff:
    def _go_diff(self):
        # Mirrors supply_chain_init.go:461 — directive on the line ABOVE a Go sink.
        return textwrap.dedent("""\
            diff --git a/internal/cmd/init.go b/internal/cmd/init.go
            +++ b/internal/cmd/init.go
            @@ -0,0 +1,2 @@
            +\t// armis:ignore cwe:78 cwe:77 reason:pms flows through sanitizePMNames
            +\tw := supplychain.GenerateWrapper(sh.Name, pms)
            """)

    def test_multi_cwe_suppresses_first_listed(self):
        diff = self._go_diff()
        line = _blob_line(diff, "GenerateWrapper")
        # Scanner reports CWE-78 (the first listed) -> suppressed via OR-match.
        active, suppressed = _run(diff, [{"cwe": 78, "severity": "HIGH", "line": line}])
        assert suppressed and active == []
        assert suppressed[0]["_suppression_source"] == "inline"

    def test_multi_cwe_suppresses_second_listed(self):
        diff = self._go_diff()
        line = _blob_line(diff, "GenerateWrapper")
        # Same directive, a run where the model reported CWE-77 instead -> also clears.
        active, suppressed = _run(diff, [{"cwe": 77, "severity": "HIGH", "line": line}])
        assert suppressed and active == []

    def test_multi_cwe_unlisted_stays_active(self):
        diff = self._go_diff()
        line = _blob_line(diff, "GenerateWrapper")
        # A CWE not in the list is NOT suppressed (no over-broad matching).
        active, suppressed = _run(diff, [{"cwe": 89, "severity": "HIGH", "line": line}])
        assert active and suppressed == []
