"""Tests for git-hooks/scan-staged.py standalone scanner.

These are subprocess-based tests that run scan-staged.py in a real temp git repo.
API calls are mocked by patching the target functions in a wrapper script.
"""

import hashlib
import json
import os
import subprocess
import sys
import textwrap

from conftest import scan_pass_path

_PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SCAN_STAGED_SCRIPT = os.path.join(_PLUGIN_ROOT, "git-hooks", "scan-staged.py")


def _init_git_repo(path, staged_content="print('hello')\n"):
    """Create a git repo with a staged file, return the staged diff hash."""
    subprocess.run(["git", "init"], cwd=str(path), capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=str(path),
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"], cwd=str(path), capture_output=True, check=True
    )

    (path / "init.txt").write_text("init")
    subprocess.run(["git", "add", "init.txt"], cwd=str(path), capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(path), capture_output=True, check=True)

    (path / "test.py").write_text(staged_content)
    subprocess.run(["git", "add", "test.py"], cwd=str(path), capture_output=True, check=True)

    result = subprocess.run(
        ["git", "diff", "--cached", "--no-color", "--no-ext-diff"],
        cwd=str(path),
        capture_output=True,
    )
    # Hash raw bytes — must match hash_utils.compute_staged_hash and scan-staged.py.
    return hashlib.sha256(result.stdout).hexdigest()


def _run_scan_staged(tmp_path, mock_response=None, mock_auth_error=None, env_override=None):
    """Run scan-staged.py via a wrapper that patches network calls.

    Instead of modifying the real script, we write a thin wrapper that:
    1. Patches auth.init_auth (to avoid real credential exchange)
    2. Patches scanner_core.call_appsec_api (to avoid real HTTP)
    3. Then calls the script's __main__ block (which has the fail-open try/except)
    """
    # Default: clean scan response (no findings)
    if mock_response is None and mock_auth_error is None:
        mock_response = "```json\n[]\n```"

    wrapper = textwrap.dedent(f"""\
        import os, sys
        plugin_dir = {repr(str(_PLUGIN_ROOT))}
        sys.path.insert(0, plugin_dir)

        # Pre-import and patch BEFORE scan-staged loads (it uses `from X import Y`)
        import auth
        import scanner_core

        mock_auth_error = {repr(mock_auth_error)}
        mock_response = {repr(mock_response)}

        def fake_init_auth(api_url):
            if mock_auth_error:
                raise RuntimeError(mock_auth_error)

        def fake_call_appsec_api(code):
            # Record the exact blob handed to the API so tests can assert on what
            # was (and was not) scanned. Absence of the file means no API call.
            with open({repr(str(tmp_path / "_scanned.txt"))}, "w") as fh:
                fh.write(code)
            return mock_response

        auth.init_auth = fake_init_auth
        scanner_core.call_appsec_api = fake_call_appsec_api

        os.chdir({repr(str(tmp_path))})

        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "scan_staged", os.path.join(plugin_dir, "git-hooks", "scan-staged.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # Replicate the __main__ block (with fail-open try/except)
        try:
            mod.main()
        except SystemExit as e:
            sys.exit(e.code)
        except Exception as e:
            print(f"appsec: scan failed — {{e}} (commit allowed)", file=sys.stderr)
            sys.exit(0)
    """)

    wrapper_path = tmp_path / "_test_wrapper.py"
    wrapper_path.write_text(wrapper)

    env = os.environ.copy()
    env["ARMIS_CLIENT_ID"] = "test-id"
    env["ARMIS_CLIENT_SECRET"] = "test-secret"
    env.pop("APPSEC_API_URL", None)
    env.pop("APPSEC_ENV", None)
    if env_override:
        env.update(env_override)

    result = subprocess.run(
        [sys.executable, str(wrapper_path)],
        capture_output=True,
        text=True,
        timeout=15,
        env=env,
        cwd=str(tmp_path),
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


class TestNoStagedChanges:
    """When there are no staged changes, exit cleanly."""

    def test_no_staged_changes_exits_zero(self, tmp_path):
        # Init repo but don't stage anything new
        subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)
        subprocess.run(
            ["git", "config", "user.email", "t@t.com"],
            cwd=str(tmp_path),
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "T"], cwd=str(tmp_path), capture_output=True, check=True
        )
        (tmp_path / "x.txt").write_text("x")
        subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True, check=True)
        subprocess.run(
            ["git", "commit", "-m", "init"], cwd=str(tmp_path), capture_output=True, check=True
        )
        # No new staged changes after commit
        stdout, stderr, rc = _run_scan_staged(tmp_path)
        assert rc == 0
        assert "no staged changes" in stderr


class TestCleanScan:
    """Clean scans (no HIGH/CRITICAL findings) should write .scan-pass."""

    def test_clean_scan_writes_scan_pass(self, tmp_path):
        _init_git_repo(tmp_path)
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response="```json\n[]\n```")
        assert rc == 0
        assert "scan clean" in stderr
        assert "scan-pass written" in stderr
        # Written inside the git dir, not the working tree.
        assert scan_pass_path(tmp_path).exists()
        assert not (tmp_path / ".scan-pass").exists()

    def test_low_medium_findings_allow_commit(self, tmp_path):
        """LOW and MEDIUM findings should NOT block — only HIGH/CRITICAL do."""
        _init_git_repo(tmp_path)
        findings = json.dumps(
            [
                {"severity": "LOW", "cwe": 79, "cwe_name": "XSS", "line": 1, "explanation": "test"},
                {
                    "severity": "MEDIUM",
                    "cwe": 89,
                    "cwe_name": "SQLi",
                    "line": 2,
                    "explanation": "test",
                },
            ]
        )
        mock_response = f"```json\n{findings}\n```"
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response=mock_response)
        assert rc == 0
        assert "scan clean" in stderr


class TestHighCriticalFindings:
    """HIGH and CRITICAL findings should block the commit."""

    def test_high_finding_exits_nonzero(self, tmp_path):
        _init_git_repo(tmp_path)
        findings = json.dumps(
            [
                {
                    "severity": "HIGH",
                    "cwe": 798,
                    "cwe_name": "Hard-coded Creds",
                    "line": 1,
                    "explanation": "password in source",
                },
            ]
        )
        mock_response = f"```json\n{findings}\n```"
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response=mock_response)
        assert rc == 1
        assert "HIGH/CRITICAL findings" in stderr

    def test_critical_finding_exits_nonzero(self, tmp_path):
        _init_git_repo(tmp_path)
        findings = json.dumps(
            [
                {
                    "severity": "CRITICAL",
                    "cwe": 78,
                    "cwe_name": "OS Command Injection",
                    "line": 1,
                    "explanation": "unsanitized input in os.system()",
                },
            ]
        )
        mock_response = f"```json\n{findings}\n```"
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response=mock_response)
        assert rc == 1
        assert "HIGH/CRITICAL findings" in stderr

    def test_mixed_findings_blocks_on_high(self, tmp_path):
        """Even with LOW findings, presence of HIGH should block."""
        _init_git_repo(tmp_path)
        findings = json.dumps(
            [
                {"severity": "LOW", "cwe": 79, "cwe_name": "XSS", "line": 1, "explanation": "low"},
                {
                    "severity": "HIGH",
                    "cwe": 502,
                    "cwe_name": "Deserialization",
                    "line": 5,
                    "explanation": "pickle.loads",
                },
            ]
        )
        mock_response = f"```json\n{findings}\n```"
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response=mock_response)
        assert rc == 1
        assert "1 HIGH/CRITICAL" in stderr


class TestAuthFailure:
    """Auth failures should fail open (exit 0)."""

    def test_auth_failure_exits_zero(self, tmp_path):
        _init_git_repo(tmp_path)
        stdout, stderr, rc = _run_scan_staged(
            tmp_path, mock_auth_error="token exchange failed: 401"
        )
        assert rc == 0
        assert "auth failed" in stderr


class TestFailOpen:
    """Unexpected exceptions should fail open (exit 0)."""

    def test_unexpected_exception_exits_zero(self, tmp_path):
        """The outer try/except in __main__ catches all unhandled exceptions."""
        _init_git_repo(tmp_path)

        # Use a mock that raises a non-SystemExit exception
        # The wrapper's outer try/except should catch it and exit 0
        wrapper = textwrap.dedent(f"""\
            import os, sys
            plugin_dir = {repr(str(_PLUGIN_ROOT))}
            sys.path.insert(0, plugin_dir)

            import auth
            import scanner_core

            def fake_init_auth(api_url):
                pass

            def fake_call_appsec_api(code):
                raise ConnectionError("network unreachable")

            auth.init_auth = fake_init_auth
            scanner_core.call_appsec_api = fake_call_appsec_api

            os.chdir({repr(str(tmp_path))})
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "scan_staged",
                os.path.join(plugin_dir, "git-hooks", "scan-staged.py")
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            try:
                mod.main()
            except SystemExit as e:
                sys.exit(e.code)
            except Exception as e:
                print(f"appsec: scan failed — {{e}} (commit allowed)", file=sys.stderr)
                sys.exit(0)
        """)

        wrapper_path = tmp_path / "_test_exception.py"
        wrapper_path.write_text(wrapper)

        env = os.environ.copy()
        env["ARMIS_CLIENT_ID"] = "test"
        env["ARMIS_CLIENT_SECRET"] = "test"

        result = subprocess.run(
            [sys.executable, str(wrapper_path)],
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
            cwd=str(tmp_path),
        )
        assert result.returncode == 0
        assert "scan failed" in result.stderr or "commit allowed" in result.stderr


class TestCWEFiltering:
    """Findings with cwe=None or cwe=0 should be filtered out by parse_findings."""

    def test_null_cwe_findings_ignored(self, tmp_path):
        _init_git_repo(tmp_path)
        findings = json.dumps(
            [
                {"severity": "HIGH", "cwe": None, "line": 1, "explanation": "no cwe"},
                {"severity": "HIGH", "cwe": 0, "line": 2, "explanation": "zero cwe"},
            ]
        )
        mock_response = f"```json\n{findings}\n```"
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response=mock_response)
        # Both findings filtered out → clean scan
        assert rc == 0


def _staged_blob_line(path, needle):
    """1-based blob line number (within `git diff --cached`) of the line with `needle`.

    Lets inline-suppression tests put the mock finding's `line` exactly where the
    directive is, without hardcoding diff offsets.
    """
    diff = subprocess.run(
        ["git", "diff", "--cached", "--no-color", "--no-ext-diff"],
        cwd=str(path),
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for i, line in enumerate(diff.splitlines(), start=1):
        if needle in line:
            return i
    raise AssertionError(f"needle {needle!r} not found in staged diff")


class TestInlineSuppression:
    """Inline armis:ignore directives in the staged diff (PPSC-903 regression).

    The git hook must agree with the MCP scan_diff flow: inline-suppressed HIGH
    allows the commit; inline-suppressed CRITICAL still blocks; a directive on a
    removed line never suppresses.
    """

    def test_inline_suppressed_high_allows_commit(self, tmp_path):
        """REGRESSION (#16): inline armis:ignore on a HIGH finding → commit allowed."""
        _init_git_repo(tmp_path, staged_content='password = "secret"  # armis:ignore cwe:798\n')
        line = _staged_blob_line(tmp_path, "password")
        findings = json.dumps(
            [
                {
                    "severity": "HIGH",
                    "cwe": 798,
                    "cwe_name": "Hard-coded Creds",
                    "line": line,
                    "explanation": "password in source",
                }
            ]
        )
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response=f"```json\n{findings}\n```")
        assert rc == 0
        assert "scan-pass written" in stderr

    def test_inline_suppressed_critical_still_blocks(self, tmp_path):
        """Inline armis:ignore on a CRITICAL finding → still blocked (needs approval)."""
        _init_git_repo(tmp_path, staged_content="os.system(x)  # armis:ignore cwe:78\n")
        line = _staged_blob_line(tmp_path, "os.system")
        findings = json.dumps(
            [
                {
                    "severity": "CRITICAL",
                    "cwe": 78,
                    "cwe_name": "OS Command Injection",
                    "line": line,
                    "explanation": "unsanitized input",
                }
            ]
        )
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response=f"```json\n{findings}\n```")
        assert rc == 1
        assert "HIGH/CRITICAL findings" in stderr

    def test_removed_line_directive_does_not_suppress(self, tmp_path):
        """A directive on a removed (-) line must NOT suppress a new HIGH finding."""
        # Commit a line bearing the directive, then replace it (so it becomes a '-' line).
        _init_git_repo(tmp_path, staged_content="value = old  # armis:ignore cwe:798\n")
        subprocess.run(
            ["git", "commit", "-m", "add"], cwd=str(tmp_path), capture_output=True, check=True
        )
        (tmp_path / "test.py").write_text("value = secret\n")
        subprocess.run(
            ["git", "add", "test.py"], cwd=str(tmp_path), capture_output=True, check=True
        )
        line = _staged_blob_line(tmp_path, "+value = secret")
        findings = json.dumps(
            [
                {
                    "severity": "HIGH",
                    "cwe": 798,
                    "cwe_name": "Hard-coded Creds",
                    "line": line,
                    "explanation": "secret",
                }
            ]
        )
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response=f"```json\n{findings}\n```")
        assert rc == 1

    def test_lowercase_critical_still_blocks(self, tmp_path):
        """REGRESSION: lowercase severity must block (git hook normalizes to .upper()).

        parse_findings does not normalize case and the model may emit "critical";
        a case-sensitive gate would write scan-pass and allow the commit, diverging
        from the MCP scan_diff flow which uses .upper() everywhere.
        """
        _init_git_repo(tmp_path, staged_content="os.system(x)\n")
        line = _staged_blob_line(tmp_path, "os.system")
        findings = json.dumps(
            [
                {
                    "severity": "critical",
                    "cwe": 78,
                    "cwe_name": "OS Command Injection",
                    "line": line,
                    "explanation": "unsanitized input",
                }
            ]
        )
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response=f"```json\n{findings}\n```")
        assert rc == 1
        assert "HIGH/CRITICAL findings" in stderr
        assert "scan-pass written" not in stderr
        assert "HIGH/CRITICAL findings" in stderr


def _scanned_text(tmp_path):
    """The exact blob the API was handed, or None if it was never called."""
    path = tmp_path / "_scanned.txt"
    return path.read_text() if path.exists() else None


def _init_git_repo_multi(path, files):
    """Commit an init file, then stage `files` ({rel_path: content}).

    Returns the sha256 of the *unfiltered* staged diff — what
    hash_utils.compute_staged_hash and git-hooks/pre-commit compute.
    """
    subprocess.run(["git", "init"], cwd=str(path), capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=str(path),
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"], cwd=str(path), capture_output=True, check=True
    )
    (path / "init.txt").write_text("init")
    subprocess.run(["git", "add", "init.txt"], cwd=str(path), capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(path), capture_output=True, check=True)

    for rel, content in files.items():
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        subprocess.run(["git", "add", rel], cwd=str(path), capture_output=True, check=True)

    result = subprocess.run(
        ["git", "diff", "--cached", "--no-color", "--no-ext-diff"],
        cwd=str(path),
        capture_output=True,
    )
    return hashlib.sha256(result.stdout).hexdigest()


class TestArmisIgnorePathExclusion:
    """`.armisignore` path patterns must exclude files from the git-hook scan.

    filter_diff_excluded_paths() shipped but was only ever called from server.py's
    scan_diff tool. In the git hook a path pattern was a silent no-op: the only
    other suppression, apply_suppressions(), matches a finding's cwe/severity/
    category and never its file — so an excluded file was still sent to the API
    and could still block the commit.
    """

    _HIGH = json.dumps(
        [
            {
                "severity": "HIGH",
                "cwe": 798,
                "cwe_name": "Hard-coded Creds",
                "line": 1,
                "explanation": "token in source",
            }
        ]
    )

    def test_excluded_file_is_dropped_from_the_scanned_diff(self, tmp_path):
        _init_git_repo_multi(
            tmp_path,
            {"app.py": "print('app')\n", "generated/schema.py": "TOKEN = 'abc123'\n"},
        )
        (tmp_path / ".armisignore").write_text("generated/\n")
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response="```json\n[]\n```")
        assert rc == 0
        scanned = _scanned_text(tmp_path)
        assert "app.py" in scanned
        assert "generated/schema.py" not in scanned
        assert "TOKEN" not in scanned

    def test_excluded_file_no_longer_blocks_the_commit(self, tmp_path):
        """The whole point of the directive: a HIGH in an excluded file cannot gate."""
        _init_git_repo_multi(tmp_path, {"generated/schema.py": "TOKEN = 'abc123'\n"})
        (tmp_path / ".armisignore").write_text("generated/\n")
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response=f"```json\n{self._HIGH}\n```")
        assert rc == 0
        # Every staged file excluded → the API is never called at all.
        assert _scanned_text(tmp_path) is None
        assert "all changed files excluded by .armisignore" in stderr

    def test_basename_pattern_excludes(self, tmp_path):
        """A pattern with no '/' matches the basename, as in .gitignore."""
        _init_git_repo_multi(tmp_path, {"src/fixtures.py": "TOKEN = 'abc123'\n"})
        (tmp_path / ".armisignore").write_text("fixtures.py\n")
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response=f"```json\n{self._HIGH}\n```")
        assert rc == 0
        assert _scanned_text(tmp_path) is None

    def test_all_excluded_writes_a_scan_pass_over_the_unfiltered_diff(self, tmp_path):
        """Nothing left to scan is a clean scan, and the handshake must still match.

        Two things are being asserted. (1) The scan-pass is written, so a repo that
        legitimately excludes every staged file is not blocked by git-hooks/pre-commit
        under APPSEC_HOOK_STRICT=1. (2) It hashes the diff *before* filtering — the
        gate reader (hash_utils.compute_staged_hash) hashes the unfiltered diff, so a
        hash over the filtered text could never match.
        """
        expected_hash = _init_git_repo_multi(tmp_path, {"generated/schema.py": "TOKEN = 'a'\n"})
        (tmp_path / ".armisignore").write_text("generated/\n")
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response="```json\n[]\n```")
        assert rc == 0
        assert _scanned_text(tmp_path) is None
        assert scan_pass_path(tmp_path).read_text().strip() == expected_hash

    def test_cwe_directive_alone_does_not_filter_the_diff(self, tmp_path):
        """A .armisignore with no path patterns must leave the diff untouched."""
        _init_git_repo_multi(tmp_path, {"app.py": "TOKEN = 'abc123'\n"})
        (tmp_path / ".armisignore").write_text("cwe:798\n")
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response=f"```json\n{self._HIGH}\n```")
        # Suppressed by cwe:798, not by path — the file was still scanned.
        assert rc == 0
        assert "app.py" in _scanned_text(tmp_path)


class TestFindingLocations:
    """Findings must be reported at a source path:line, not a diff-blob line.

    format_findings() can translate a finding's blob line number into the real
    path:line, but only when handed the line_map that build_diff_line_map()
    produces. scan-staged.py computed that map (it needs it for inline
    suppression) and then called format_findings() without it, so every finding
    printed as a bare `L<blob line>` — offset by the diff headers, and
    indistinguishable from a file line number to whoever reads the failure.
    """

    def test_blocking_finding_reports_source_path_and_line(self, tmp_path):
        # Token on source line 4. The diff header lines push it further down the
        # blob, so an unmapped report cannot name line 4.
        content = "import os\n\n\nTOKEN = 'abc123'\n"
        _init_git_repo(tmp_path, staged_content=content)
        blob_line = _staged_blob_line(tmp_path, "TOKEN")
        assert blob_line != 4, "fixture must separate blob line from source line"
        findings = json.dumps(
            [
                {
                    "severity": "HIGH",
                    "cwe": 798,
                    "cwe_name": "Hard-coded Creds",
                    "line": blob_line,
                    "explanation": "token in source",
                }
            ]
        )
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response=f"```json\n{findings}\n```")
        assert rc == 1
        assert "test.py:4" in stderr
        assert f"L{blob_line}" not in stderr

    def test_unmappable_line_still_falls_back(self, tmp_path):
        """A finding whose line is outside the map must still print, not crash."""
        _init_git_repo(tmp_path, staged_content="TOKEN = 'abc123'\n")
        findings = json.dumps(
            [
                {
                    "severity": "CRITICAL",
                    "cwe": 798,
                    "cwe_name": "Hard-coded Creds",
                    "line": 9999,
                    "explanation": "token in source",
                }
            ]
        )
        stdout, stderr, rc = _run_scan_staged(tmp_path, mock_response=f"```json\n{findings}\n```")
        assert rc == 1
        assert "L9999" in stderr
