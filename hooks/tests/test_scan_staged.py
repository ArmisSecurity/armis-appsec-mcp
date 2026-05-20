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

_PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SCAN_STAGED_SCRIPT = os.path.join(_PLUGIN_ROOT, "git-hooks", "scan-staged.py")


def _init_git_repo(path, staged_content="print('hello')\n"):
    """Create a git repo with a staged file, return the staged diff hash."""
    subprocess.run(["git", "init"], cwd=str(path), capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"], cwd=str(path), capture_output=True
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(path), capture_output=True)

    (path / "init.txt").write_text("init")
    subprocess.run(["git", "add", "init.txt"], cwd=str(path), capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(path), capture_output=True)

    (path / "test.py").write_text(staged_content)
    subprocess.run(["git", "add", "test.py"], cwd=str(path), capture_output=True)

    result = subprocess.run(
        ["git", "diff", "--cached", "--no-color", "--no-ext-diff"],
        cwd=str(path),
        capture_output=True,
        text=True,
    )
    return hashlib.sha256(result.stdout.encode()).hexdigest()


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
            ["git", "config", "user.email", "t@t.com"], cwd=str(tmp_path), capture_output=True
        )
        subprocess.run(["git", "config", "user.name", "T"], cwd=str(tmp_path), capture_output=True)
        (tmp_path / "x.txt").write_text("x")
        subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=str(tmp_path), capture_output=True)
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
        assert ".scan-pass written" in stderr

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
