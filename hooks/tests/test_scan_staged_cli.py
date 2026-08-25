"""Tests for hooks/scan_staged_cli.py -- the three scan sources and the fail policy.

Covers what the upstream git-hook scanner could not do:
  * --ref mode, so a CI checkout with nothing staged is actually scanned
  * .armisignore *path* patterns, which the git hook silently ignored
  * file-argument mode, so `pre-commit run --all-files` scans something
  * --strict / APPSEC_HOOK_STRICT turning fail-open into fail-closed

Same shape as test_scan_staged.py: a real temp git repo, and a wrapper script that
patches auth/HTTP before the CLI imports them.
"""

import json
import os
import subprocess
import sys
import textwrap

_PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_HIGH_FINDING = json.dumps(
    [
        {
            "severity": "HIGH",
            "cwe": 89,
            "line": 5,
            # parse_findings/format_findings use "explanation", not "description" --
            # a finding built with the wrong key renders with an empty message.
            "explanation": "SQL injection: concatenated query",
        }
    ]
)
_CLEAN = "```json\n[]\n```"


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, check=True)


def _init_repo(path):
    # conftest's autouse _ensure_tmp_is_git_repo has already run a plain `git init`,
    # so `git init -b main` here is a re-init that does NOT rename the unborn branch --
    # the default stays whatever init.defaultBranch is. Check out the branch explicitly
    # on the unborn HEAD instead, so `--ref main` resolves regardless of git config.
    _git(["init"], path)
    _git(["checkout", "-b", "main"], path)
    _git(["config", "user.email", "t@t.com"], path)
    _git(["config", "user.name", "T"], path)
    (path / "init.txt").write_text("init")
    _git(["add", "init.txt"], path)
    _git(["commit", "-m", "init"], path)


def _run_cli(tmp_path, argv, mock_response=_CLEAN, mock_auth_error=None, env_override=None):
    """Run the CLI's main() with argv, network patched. Returns (stdout, stderr, rc)."""
    wrapper = textwrap.dedent(f"""\
        import os, sys
        sys.path.insert(0, {repr(str(_PLUGIN_ROOT))})

        import auth, scanner_core

        mock_auth_error = {repr(mock_auth_error)}
        mock_response = {repr(mock_response)}
        captured = {{}}

        def fake_init_auth(api_url):
            if mock_auth_error:
                raise RuntimeError(mock_auth_error)

        def fake_call_appsec_api(code):
            captured["code"] = code
            print("CAPTURED_CHARS=%d" % len(code))
            print("CAPTURED_CODE_START")
            print(code)
            print("CAPTURED_CODE_END")
            return mock_response

        auth.init_auth = fake_init_auth
        scanner_core.call_appsec_api = fake_call_appsec_api

        os.chdir({repr(str(tmp_path))})
        from hooks import scan_staged_cli
        scan_staged_cli.call_appsec_api = fake_call_appsec_api
        scan_staged_cli.init_auth = fake_init_auth
        sys.argv = ["armis-scan-staged"] + {repr(argv)}
        scan_staged_cli.cli_main()
    """)
    wrapper_path = tmp_path / "_cli_wrapper.py"
    wrapper_path.write_text(wrapper)

    env = os.environ.copy()
    env["ARMIS_CLIENT_ID"] = "test-id"
    env["ARMIS_CLIENT_SECRET"] = "test-secret"
    env.pop("APPSEC_API_URL", None)
    env.pop("APPSEC_ENV", None)
    env.pop("APPSEC_HOOK_STRICT", None)
    if env_override:
        env.update(env_override)

    result = subprocess.run(
        [sys.executable, str(wrapper_path)],
        capture_output=True,
        text=True,
        timeout=20,
        env=env,
        cwd=str(tmp_path),
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


class TestRefMode:
    """--ref closes the CI gap: a fresh checkout has nothing staged."""

    def test_ref_diff_blocks_on_high(self, tmp_path):
        _init_repo(tmp_path)
        _git(["checkout", "-b", "feature"], tmp_path)
        (tmp_path / "app.py").write_text("q = 'SELECT ' + user\n")
        _git(["add", "app.py"], tmp_path)
        _git(["commit", "-m", "add app"], tmp_path)

        _out, stderr, rc = _run_cli(
            tmp_path, ["--ref", "main"], mock_response=f"```json\n{_HIGH_FINDING}\n```"
        )
        assert rc == 1, stderr
        assert "HIGH/CRITICAL findings" in stderr

    def test_staged_mode_finds_nothing_on_committed_branch(self, tmp_path):
        """The exact CI failure mode: committed work, empty index -> vacuous pass."""
        _init_repo(tmp_path)
        (tmp_path / "app.py").write_text("q = 'SELECT ' + user\n")
        _git(["add", "app.py"], tmp_path)
        _git(["commit", "-m", "add app"], tmp_path)

        _out, stderr, rc = _run_cli(tmp_path, [], mock_response=f"```json\n{_HIGH_FINDING}\n```")
        assert rc == 0
        assert "no staged changes" in stderr

    def test_ref_mode_does_not_write_scan_pass(self, tmp_path):
        """A ref scan makes no claim about the index, so it must not write the token."""
        _init_repo(tmp_path)
        _git(["checkout", "-b", "feature"], tmp_path)
        (tmp_path / "app.py").write_text("x = 1\n")
        _git(["add", "app.py"], tmp_path)
        _git(["commit", "-m", "c"], tmp_path)

        _out, stderr, rc = _run_cli(tmp_path, ["--ref", "main"])
        assert rc == 0, stderr
        # rc==0 alone would also be satisfied by the fail-open path, so require
        # positive evidence that the ref diff really reached the scanner.
        assert "scan clean" in stderr
        assert "CAPTURED_CHARS" in _out
        assert "scan-pass written" not in stderr


class TestArmisignorePathPatterns:
    """Path patterns were parsed but never applied in the git-hook scanner."""

    def test_excluded_path_is_not_scanned(self, tmp_path):
        _init_repo(tmp_path)
        (tmp_path / ".armisignore").write_text("notebooks/\n")
        os.makedirs(tmp_path / "notebooks")
        (tmp_path / "notebooks" / "explore.py").write_text("q = 'SELECT ' + user\n")
        _git(["add", "-A"], tmp_path)

        _out, stderr, rc = _run_cli(tmp_path, [], mock_response=f"```json\n{_HIGH_FINDING}\n```")
        # .armisignore itself is still staged, so the scan does run -- but the excluded
        # file's diff section must have been stripped before the API call.
        assert "CAPTURED_CODE_START" in _out, stderr
        sent = _out.split("CAPTURED_CODE_START", 1)[1].split("CAPTURED_CODE_END", 1)[0]
        assert "notebooks/explore.py" not in sent
        assert "SELECT" not in sent
        assert ".armisignore" in sent  # proves the diff was filtered, not emptied

    def test_all_paths_excluded_short_circuits(self, tmp_path):
        _init_repo(tmp_path)
        (tmp_path / ".armisignore").write_text("*.py\n")
        _git(["add", ".armisignore"], tmp_path)
        _git(["commit", "-m", "ignore"], tmp_path)
        (tmp_path / "bad.py").write_text("q = 'SELECT ' + user\n")
        _git(["add", "bad.py"], tmp_path)

        _out, stderr, rc = _run_cli(tmp_path, [], mock_response=f"```json\n{_HIGH_FINDING}\n```")
        assert rc == 0, stderr
        assert "excluded by .armisignore" in stderr
        assert "CAPTURED_CHARS" not in _out  # API never called


class TestFilesMode:
    """`pre-commit run --all-files` passes filenames, not a diff."""

    def test_file_args_are_scanned_and_block(self, tmp_path):
        _init_repo(tmp_path)
        (tmp_path / "app.py").write_text("q = 'SELECT ' + user\n")

        _out, stderr, rc = _run_cli(
            tmp_path, ["app.py"], mock_response=f"```json\n{_HIGH_FINDING}\n```"
        )
        assert rc == 1, stderr
        assert "HIGH/CRITICAL findings" in stderr
        assert "CAPTURED_CHARS" in _out  # the file content really was sent

    def test_file_args_respect_armisignore_paths(self, tmp_path):
        _init_repo(tmp_path)
        (tmp_path / ".armisignore").write_text("app.py\n")
        (tmp_path / "app.py").write_text("q = 'SELECT ' + user\n")

        _out, stderr, rc = _run_cli(
            tmp_path, ["app.py"], mock_response=f"```json\n{_HIGH_FINDING}\n```"
        )
        assert rc == 0, stderr
        assert "no scannable files after exclusions" in stderr

    def test_non_source_files_skipped(self, tmp_path):
        _init_repo(tmp_path)
        (tmp_path / "data.parquet").write_text("binary-ish")

        _out, stderr, rc = _run_cli(tmp_path, ["data.parquet"])
        assert rc == 0, stderr
        assert "no scannable files after exclusions" in stderr

    def test_files_mode_does_not_write_scan_pass(self, tmp_path):
        _init_repo(tmp_path)
        (tmp_path / "app.py").write_text("x = 1\n")

        _out, stderr, rc = _run_cli(tmp_path, ["app.py"])
        assert rc == 0, stderr
        assert "scan-pass written" not in stderr


class TestFailPolicy:
    """Fail-open by default; --strict / APPSEC_HOOK_STRICT flips it."""

    def test_auth_failure_fails_open_by_default(self, tmp_path):
        _init_repo(tmp_path)
        (tmp_path / "app.py").write_text("x = 1\n")
        _git(["add", "app.py"], tmp_path)

        _out, stderr, rc = _run_cli(tmp_path, [], mock_auth_error="no creds")
        assert rc == 0
        assert "auth failed" in stderr

    def test_auth_failure_fails_closed_with_strict_flag(self, tmp_path):
        _init_repo(tmp_path)
        (tmp_path / "app.py").write_text("x = 1\n")
        _git(["add", "app.py"], tmp_path)

        _out, stderr, rc = _run_cli(tmp_path, ["--strict"], mock_auth_error="no creds")
        assert rc == 1
        assert "auth failed" in stderr

    def test_auth_failure_fails_closed_with_env(self, tmp_path):
        _init_repo(tmp_path)
        (tmp_path / "app.py").write_text("x = 1\n")
        _git(["add", "app.py"], tmp_path)

        _out, stderr, rc = _run_cli(
            tmp_path, [], mock_auth_error="no creds", env_override={"APPSEC_HOOK_STRICT": "1"}
        )
        assert rc == 1


class TestTruncation:
    """The upstream git-hook scanner had no char limit; server.py capped at 90k."""

    def test_oversized_input_is_truncated(self, tmp_path):
        _init_repo(tmp_path)
        from hooks.scan_staged_cli import MAX_CODE_CHARS

        big = "\n".join(f"x{i} = {i}" for i in range(20_000)) + "\n"
        (tmp_path / "big.py").write_text(big)
        assert len(big) > MAX_CODE_CHARS

        out, stderr, rc = _run_cli(tmp_path, ["big.py"])
        assert rc == 0, stderr
        assert "exceeds" in stderr
        captured = int(out.split("CAPTURED_CHARS=")[1].split()[0])
        assert captured == MAX_CODE_CHARS


class TestFindingLocations:
    """Findings must be reported at a source path:line, not a diff-blob line.

    The blob line is offset by the synthesized/real diff headers, so an unmapped
    report reads as a file line and points at the wrong code. format_findings()
    can translate it, but only when handed the line_map.
    """

    def test_files_mode_reports_source_path_and_line(self, tmp_path):
        _init_repo(tmp_path)
        # Token on source line 6; the 5 synthesized diff header lines put it at
        # blob line 11, which is what an unmapped report would print.
        (tmp_path / "app.py").write_text(
            '# header\nimport os\n\nimport requests\n\nTOKEN = "dapi0000000000000000000000000000"\n'
        )
        finding = json.dumps(
            [
                {
                    "severity": "HIGH",
                    "cwe": 798,
                    "line": 11,
                    "explanation": "hard-coded token",
                }
            ]
        )
        _out, stderr, rc = _run_cli(tmp_path, ["app.py"], mock_response=f"```json\n{finding}\n```")
        assert rc == 1, stderr
        assert "app.py:6" in stderr
        assert "L11" not in stderr

    def test_staged_mode_reports_source_path_and_line(self, tmp_path):
        _init_repo(tmp_path)
        (tmp_path / "app.py").write_text("import os\nx = 1\ny = 2\n")
        _git(["add", "app.py"], tmp_path)

        # A real staged diff for a new file has 6 header lines (diff --git, new file
        # mode, index, ---, +++, @@) -- one more than the synthesized files-mode diff,
        # which has no `index` line. So source line 2 sits at blob line 8.
        finding = json.dumps([{"severity": "HIGH", "cwe": 89, "line": 8, "explanation": "bad"}])
        _out, stderr, rc = _run_cli(
            tmp_path, ["--staged"], mock_response=f"```json\n{finding}\n```"
        )
        assert rc == 1, stderr
        assert "app.py:2" in stderr


class TestWarnOnly:
    """--warn-only reports but never blocks; the report itself must be unchanged."""

    def test_warn_only_reports_and_exits_zero(self, tmp_path):
        _init_repo(tmp_path)
        (tmp_path / "app.py").write_text("q = 'SELECT ' + user\n")

        _out, stderr, rc = _run_cli(
            tmp_path, ["--warn-only", "app.py"], mock_response=f"```json\n{_HIGH_FINDING}\n```"
        )
        assert rc == 0, stderr
        assert "SQL injection" in stderr
        assert "warn-only, not blocking" in stderr
        assert "Fix before committing" not in stderr

    def test_without_warn_only_the_same_input_blocks(self, tmp_path):
        _init_repo(tmp_path)
        (tmp_path / "app.py").write_text("q = 'SELECT ' + user\n")

        _out, stderr, rc = _run_cli(
            tmp_path, ["app.py"], mock_response=f"```json\n{_HIGH_FINDING}\n```"
        )
        assert rc == 1
        assert "Fix before committing" in stderr


class TestChunking:
    """A repo-sized input must be split into several requests, not truncated.

    `pre-commit run --all-files` on a real 50-file project synthesizes ~317k chars.
    Truncating to one 90k request reported the remaining ~70% as clean without ever
    sending it -- a green run that scanned less than a third of the tree.
    """

    def _two_big_files(self, tmp_path, chars_each=60_000):
        body = "\n".join(f"x{i} = {i}" for i in range(chars_each // 10)) + "\n"
        (tmp_path / "a.py").write_text(body)
        (tmp_path / "b.py").write_text(body)
        return body

    def test_oversized_file_set_is_split_not_truncated(self, tmp_path):
        _init_repo(tmp_path)
        from hooks.scan_staged_cli import MAX_CODE_CHARS

        self._two_big_files(tmp_path)
        out, stderr, rc = _run_cli(tmp_path, ["a.py", "b.py"])
        assert rc == 0, stderr

        sizes = [int(chunk.split()[0]) for chunk in out.split("CAPTURED_CHARS=")[1:]]
        assert len(sizes) == 2, f"expected 2 requests, got {len(sizes)}: {sizes}"
        assert all(s <= MAX_CODE_CHARS for s in sizes), sizes
        assert "scanning in 2 request(s)" in stderr

    def test_every_file_reaches_the_scanner_when_split(self, tmp_path):
        _init_repo(tmp_path)
        self._two_big_files(tmp_path)
        out, stderr, rc = _run_cli(tmp_path, ["a.py", "b.py"])
        assert rc == 0, stderr
        # Both files must appear in some request; upstream only ever sent the first.
        assert "+++ b/a.py" in out
        assert "+++ b/b.py" in out

    def test_findings_are_aggregated_across_chunks(self, tmp_path):
        _init_repo(tmp_path)
        self._two_big_files(tmp_path)
        # Every request returns one HIGH, so a correct aggregation reports two.
        out, stderr, rc = _run_cli(
            tmp_path, ["a.py", "b.py"], mock_response=f"```json\n{_HIGH_FINDING}\n```"
        )
        assert rc == 1, stderr
        assert "2 HIGH/CRITICAL findings" in stderr

    def test_small_input_still_makes_one_request(self, tmp_path):
        _init_repo(tmp_path)
        (tmp_path / "small.py").write_text("x = 1\n")
        out, stderr, rc = _run_cli(tmp_path, ["small.py"])
        assert rc == 0, stderr
        assert out.count("CAPTURED_CHARS=") == 1
        assert "exceeds" not in stderr
