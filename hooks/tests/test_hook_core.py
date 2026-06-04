"""Tests for hooks/hook_core.py shared gate logic."""

import hashlib
import json
import os
import subprocess
import sys

import pytest
from conftest import scan_pass_path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import hook_core


class TestIsShippingCommand:
    @pytest.mark.parametrize(
        "cmd",
        [
            "git commit -m 'msg'",
            "git push",
            "git push origin main",
            "gh pr create --title 'PR'",
            "git add . && git commit -m 'msg'",
            "echo done; git push",
        ],
    )
    def test_shipping_commands(self, cmd):
        assert hook_core._is_shipping_command(cmd)

    @pytest.mark.parametrize(
        "cmd",
        ["git status", "git diff", "ls -la", "python app.py", "git add ."],
    )
    def test_non_shipping_commands(self, cmd):
        assert not hook_core._is_shipping_command(cmd)

    @pytest.mark.parametrize(
        "cmd",
        [
            # Bug-hunt #2: bypass family that the old anchor set let through.
            "echo hi\ngit commit -m x",  # newline-separated 2nd line
            "sleep 0 & git commit -m x",  # single-& separator
            "true | git commit -m x",  # pipe separator
            "git -C /repo commit -m x",  # -C global option (idiomatic in worktrees)
            "git -c user.name=x commit -m x",  # -c k=v global option
            "git --no-pager commit -m x",  # --no-pager global option
            "git --git-dir=/r/.git commit -m x",  # --git-dir global option
            "(git commit -m x)",  # subshell
            "$(git commit -m x)",  # command substitution
            "/usr/bin/git commit -m x",  # absolute path to binary
            "./git commit -m x",  # relative path to binary
            "env git commit -m x",  # env prefix
            "GIT_AUTHOR_DATE=x git commit -m x",  # env-assignment prefix
            "git -C /repo push",  # global option before push
            "env gh pr create",  # env prefix before gh pr create
            # C2: command-wrapper prefixes that exec a real shipping command.
            "command git commit -m x",  # `command` builtin
            "sudo git commit -m x",  # sudo
            "xargs git commit",  # xargs
            "eval 'git commit -m x'",  # eval with quoted command
            "nice git commit -m x",  # nice
            "time git push",  # time
            "nohup git push",  # nohup
            "\\git commit -m x",  # escaped binary (suppresses alias)
            "command gh pr create",  # wrapper before gh pr create
            # gh global options before the subcommand (deep-review #5): gh got no
            # _GH_GLOBAL_OPTS analogue when git did, so `gh --repo` slipped past.
            "gh --repo o/r pr create",  # gh --repo global option
            "gh -R o/r pr create",  # gh -R short form
            "gh --repo=o/r pr create",  # gh --repo=value form
            # Wrappers whose option takes a separate-token value, and `timeout`'s
            # leading duration positional (deep-review #8): the old _CMD_WRAP only
            # ate contiguous dash-tokens, so a separate value broke the chain.
            "sudo -u root git commit -m x",  # sudo -u <user>
            "nice -n 10 git commit -m x",  # nice -n <prio>
            "xargs -n 1 git commit",  # xargs -n <max-args>
            "timeout 5 git commit -m x",  # timeout <dur> (bare positional)
            "timeout 5s git push",  # timeout <dur+unit>
            'GIT_COMMITTER_NAME="John Doe" git commit -m x',  # quoted env value w/ space
            # git/gh long global options whose VALUE is a separate token (PR #19
            # review): the regex must consume both `--opt` and its argument or
            # _GIT_PREFIX fails at the value and the subcommand bypasses the gate.
            "git --git-dir /r/.git commit -m x",  # --git-dir <dir>
            "git --work-tree /repo push",  # --work-tree <dir>
            "git --git-dir /r/.git --work-tree /r push",  # two separate-token opts
            # `env` with flags before git/gh (PR #19 review): _ENV_PREFIX used to
            # match only a bare `env`, so `env -i`/`env -u FOO` bypassed the gate.
            "env -i git commit -m x",  # env -i (clean environment)
            "env -u FOO git push",  # env -u <name> (separate-token value)
            "env -i -u FOO git commit -m x",  # multiple env flags
            "env --ignore-environment git push",  # long env flag
            "env -i gh pr create",  # env flag before gh pr create
            "sudo env -i git commit -m x",  # wrapper + env flags chained
            "env -i GIT_AUTHOR_DATE=x git commit -m x",  # env flag then assignment
        ],
    )
    def test_shipping_bypass_family_now_caught(self, cmd):
        assert hook_core._is_shipping_command(cmd)

    @pytest.mark.parametrize(
        "cmd",
        [
            # gh global options must NOT make a non-shipping gh command match
            # (the global-opts segment is shared with git, so guard against it
            # swallowing the subcommand for a non-create gh invocation).
            "gh --repo o/r issue list",
            "gh --repo o/r pr view",
            "gh repo view",
            # `env` with flags must not make a non-git command match: the env-flag
            # run is greedy, so guard it doesn't swallow a non-shipping binary.
            "env -i ./configure",
            "env -u FOO make build",
        ],
    )
    def test_gh_global_opts_do_not_overmatch(self, cmd):
        assert not hook_core._is_shipping_command(cmd)

    @pytest.mark.parametrize(
        "cmd",
        [
            "echo 'I will commit later'",  # "commit" inside unrelated text
            "git describe",
            # Plumbing subcommands that share a prefix but are NOT shipping —
            # commit(?![-\w]) / push(?![-\w]) must not match at the hyphen.
            "git commit-tree HEAD^{tree}",
            "git commit-graph write",
            "git push-cert",
        ],
    )
    def test_commit_in_message_text_is_not_shipping(self, cmd):
        assert not hook_core._is_shipping_command(cmd)


class TestIsPushOrPr:
    def test_push(self):
        assert hook_core._is_push_or_pr("git push")
        assert hook_core._is_push_or_pr("git push origin main")

    def test_pr_create(self):
        assert hook_core._is_push_or_pr("gh pr create --title 'x'")

    def test_commit_is_not_push(self):
        assert not hook_core._is_push_or_pr("git commit -m 'x'")


class TestHasAllFlag:
    def test_short_flag(self):
        assert hook_core._has_all_flag("git commit -a -m 'msg'")

    def test_long_flag(self):
        assert hook_core._has_all_flag("git commit --all -m 'msg'")

    def test_no_flag(self):
        assert not hook_core._has_all_flag("git commit -m 'msg'")

    def test_all_flag_with_global_opts(self):
        # Bug-hunt #2: -a/--all must still be detected behind git global options
        # so build_system_message recommends scan_diff() (unstaged) correctly.
        assert hook_core._has_all_flag("git -C /repo commit -a -m 'msg'")
        assert hook_core._has_all_flag("git -c k=v commit --all")


class TestScanPassWriteForgery:
    """Bug-hunt #5: the scan-pass must be unforgeable via shell. The pattern
    denies WRITE *contexts* (redirect target, write-capable command naming the
    file, or assigning its path to a variable) — NOT mere mentions, which would
    block legitimate commands that only name the file (commit messages,
    grep/cat/rm/pytest). The hash match and protect_scan_pass.py's Write/Edit
    guard provide defense-in-depth; an HMAC token is the durable follow-up."""

    @pytest.mark.parametrize(
        "cmd",
        [
            "echo h > .git/armis-scan-pass",  # redirect
            "echo h >> .git/armis-scan-pass",  # append redirect
            "echo h > .scan-pass",  # legacy name
            "echo h | tee .git/armis-scan-pass",  # tee
            "cp /tmp/x .git/armis-scan-pass",  # cp
            "mv /tmp/x .git/armis-scan-pass",  # mv
            "dd of=.git/armis-scan-pass",  # dd (previously evaded)
            "sed -i s/a/b/ .git/armis-scan-pass",  # sed -i (previously evaded)
            "truncate -s0 .git/armis-scan-pass",  # truncate (previously evaded)
            "install /tmp/x .git/armis-scan-pass",  # install (previously evaded)
            "ln -s /tmp/x .git/armis-scan-pass",  # ln (previously evaded)
            "ex .git/armis-scan-pass",  # ex editor (previously evaded)
            "vim .git/armis-scan-pass",  # bare-arg editor (previously evaded)
            "python -c \"open('.git/armis-scan-pass','w').write('x')\"",  # python (evaded)
            "F=.git/armis-scan-pass; cat $F",  # assignment target (evaded)
            # deep-review #3 REGRESSION: the older `[>|][^;&|]*name` pattern caught
            # these, but the verb-enumeration rewrite dropped them. Restore them.
            "echo h >| .git/armis-scan-pass",  # noclobber-override redirect
            "echo h >|.git/armis-scan-pass",  # >| with no space
            "echo h 1>| .git/armis-scan-pass",  # fd-prefixed clobber redirect
            "echo x | sponge .git/armis-scan-pass",  # sponge (moreutils)
            "gawk 'BEGIN{print}' .git/armis-scan-pass",  # gawk
            "php -r x .git/armis-scan-pass",  # php interpreter
        ],
    )
    def test_forgery_vectors_denied(self, cmd):
        assert hook_core._is_scan_pass_write_bash(cmd)
        assert hook_core.check_gate(cmd).decision == "deny"

    @pytest.mark.parametrize(
        "cmd",
        [
            "echo 'scan-passed the test'",  # substring, not the basename
            "cat my-armis-scan-passport",  # word boundary: 'passport' != basename
            "echo h > out.txt",  # unrelated redirect
            "git status",  # unrelated command
            # C1 regression: legitimate commands that only NAME the file must
            # NOT be flagged as forgery (they aren't writes).
            "git commit -m 'fix armis-scan-pass path'",  # commit-message mention
            'gh pr create --title "harden armis-scan-pass"',  # PR-title mention
            "grep armis-scan-pass hooks/hook_core.py",  # search the codebase
            "cat .git/armis-scan-pass",  # read-only inspection
            "rm .git/armis-scan-pass",  # delete to force a re-scan (not a forgery)
            "pytest -k armis-scan-pass",  # test selector
        ],
    )
    def test_no_false_positives(self, cmd):
        assert not hook_core._is_scan_pass_write_bash(cmd)

    def test_commit_message_mention_reaches_shipping_gate_not_forgery(self, tmp_path):
        # C1: a real `git commit` whose message names the file must hit the
        # SHIPPING gate (scan-required message), not the forgery deny — the
        # forgery check runs first, so an over-broad pattern would shadow it.
        subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
        old_cwd = os.getcwd()
        os.chdir(str(tmp_path))
        try:
            result = hook_core.check_gate("git commit -m 'fix armis-scan-pass path'")
            assert result.decision == "deny"
            assert "Security scan required" in result.system_message
            assert "BLOCKED" not in result.system_message
        finally:
            os.chdir(old_cwd)


class TestRegexComplexity:
    """deep-review #4: the shipping/forgery grammar uses nested quantified
    alternations. An earlier `_GIT_GLOBAL_OPTS` form (`-[A-Za-z]\\s+\\S+|…`)
    backtracked catastrophically on `git ` + a long all-dash run (no subcommand),
    and the forgery arm-3 (`[A-Za-z_]\\w*=…`, unanchored) was quadratic on a long
    word-char token. Either could push `check_gate` past the PreToolUse hook's
    10s timeout — and a timed-out gate fails open (unscanned commit ships). These
    patterns run on EVERY shell command, so they MUST be linear. This test feeds
    adversarial inputs and asserts each detector returns well within budget; it
    is the guard that would have caught the original ReDoS.
    """

    # Generous ceiling: the real risk is multi-second (10s hook timeout). A
    # correct (linear) matcher finishes a 20k-char adversarial input in single-
    # digit milliseconds; 1s leaves huge headroom while still catching a
    # super-linear regression long before it reaches the hook timeout.
    _BUDGET_S = 1.0

    @pytest.mark.parametrize(
        "make_input",
        [
            lambda: "git " + "-x " * 4000,  # all-dash global-opt run (the original ReDoS)
            lambda: "git " + "-a b " * 4000,  # flag + separate value run
            lambda: "git " + "--opt " * 4000,  # long-opt run
            lambda: "gh " + "-x " * 4000,  # gh now shares the global-opts segment
            lambda: "sudo " * 8000,  # wrapper-keyword spam
            lambda: "sudo " + "-u x " * 4000,  # wrapper + separate-value spam
            lambda: "timeout " + "5 " * 4000,  # timeout duration spam
            lambda: "env " + 'A="x y" ' * 4000,  # quoted env-assignment spam
            lambda: "env " + "-u x " * 4000,  # env-flag + separate-value spam
            lambda: "env " + "-i " * 8000,  # env-flag (no value) spam
            lambda: "a" * 40000,  # long word-char token (forgery arm-3)
            lambda: "tee " + "a" * 40000,  # write verb + long token (forgery arm-2)
            lambda: "git " + "-x " * 4000 + "&& git commit -m x",  # opt-spam then real commit
        ],
    )
    def test_detectors_are_linear_on_adversarial_input(self, make_input):
        import time

        cmd = make_input()
        for detector in (
            hook_core._is_scan_pass_write_bash,
            hook_core._is_shipping_command,
            hook_core._is_push_or_pr,
            hook_core._has_all_flag,
        ):
            t0 = time.perf_counter()
            detector(cmd)
            elapsed = time.perf_counter() - t0
            assert elapsed < self._BUDGET_S, (
                f"{detector.__name__} took {elapsed:.2f}s on a "
                f"{len(cmd)}-char adversarial input (possible ReDoS regression)"
            )


class TestIsScanPassFile:
    def test_basename_match(self):
        # Current name
        assert hook_core.is_scan_pass_file("/some/path/armis-scan-pass")
        assert hook_core.is_scan_pass_file("armis-scan-pass")
        # Legacy name still blocked
        assert hook_core.is_scan_pass_file("/some/path/.scan-pass")
        assert hook_core.is_scan_pass_file(".scan-pass")

    def test_not_scan_pass(self):
        assert not hook_core.is_scan_pass_file("/some/path/file.py")
        assert not hook_core.is_scan_pass_file("scan-pass")
        assert not hook_core.is_scan_pass_file("")
        assert not hook_core.is_scan_pass_file(None)


class TestCheckGate:
    def test_non_shipping_allows(self):
        result = hook_core.check_gate("git status")
        assert result.decision == "allow"
        assert result.system_message == ""

    def test_scan_pass_write_denies(self):
        result = hook_core.check_gate("echo hash > /path/.scan-pass")
        assert result.decision == "deny"
        assert "BLOCKED" in result.system_message

    def test_armis_scan_pass_write_denies(self):
        result = hook_core.check_gate("echo hash > /path/armis-scan-pass")
        assert result.decision == "deny"
        assert "BLOCKED" in result.system_message

    def test_scan_pass_tee_denies(self):
        result = hook_core.check_gate("tee /path/.scan-pass")
        assert result.decision == "deny"
        assert "BLOCKED" in result.system_message

    def test_armis_scan_pass_tee_denies(self):
        result = hook_core.check_gate("tee /path/armis-scan-pass")
        assert result.decision == "deny"
        assert "BLOCKED" in result.system_message

    def test_shipping_without_scan_pass_denies(self, tmp_path):
        subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
        old_cwd = os.getcwd()
        os.chdir(str(tmp_path))
        try:
            # Fresh repo, no scan-pass in its git dir → deny.
            result = hook_core.check_gate("git commit -m 'msg'")
            assert result.decision == "deny"
            assert "Security scan required" in result.system_message
        finally:
            os.chdir(old_cwd)

    def test_shipping_with_valid_scan_pass_allows(self, tmp_path):
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
        # Create a file, stage it, compute hash, write .scan-pass
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")
        subprocess.run(["git", "add", "test.py"], cwd=str(tmp_path), capture_output=True)
        diff_result = subprocess.run(
            ["git", "diff", "--cached", "--no-color", "--no-ext-diff"],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
        )
        staged_hash = hashlib.sha256(diff_result.stdout.encode()).hexdigest()

        old_cwd = os.getcwd()
        os.chdir(str(tmp_path))
        try:
            # Write the scan-pass where the gate (resolving via CWD git) reads it.
            scan_pass_path(tmp_path).write_text(staged_hash)
            result = hook_core.check_gate("git commit -m 'msg'")
            assert result.decision == "allow"
        finally:
            os.chdir(old_cwd)


class TestBuildSystemMessage:
    """build_system_message weaves the hook's work-tree root into the
    recommended scan_diff call (repo_path=...), so the MCP server scans — and
    writes the scan-pass into — the same repo the commit happens in, even when
    the long-lived server is pinned to a sibling checkout. Passing repo_path
    explicitly here keeps the assertions independent of the test's real CWD."""

    def test_commit_gets_staged(self):
        msg = hook_core.build_system_message("git commit -m 'x'", repo_path="/wt")
        assert "scan_diff(staged=True, repo_path='/wt')" in msg

    def test_commit_a_gets_unstaged(self):
        msg = hook_core.build_system_message("git commit -a -m 'x'", repo_path="/wt")
        assert "scan_diff(repo_path='/wt')" in msg

    def test_push_gets_ref(self):
        msg = hook_core.build_system_message("git push", repo_path="/wt")
        assert "scan_diff(ref='origin/HEAD', repo_path='/wt')" in msg

    def test_no_repo_path_omits_arg(self):
        """Outside a git repo (repo_path resolves to None), fall back to the
        bare call — no repo_path argument to inject."""
        msg = hook_core.build_system_message("git commit -m 'x'", repo_path="")
        assert "scan_diff(staged=True)" in msg
        assert "repo_path" not in msg

    def test_default_resolves_worktree_root(self, tmp_path, monkeypatch):
        """With no explicit repo_path, it resolves the hook's CWD work-tree
        root and injects it — this is the production path."""
        subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)
        monkeypatch.chdir(tmp_path)
        msg = hook_core.build_system_message("git commit -m 'x'")
        # git's --show-toplevel is symlink-resolved; compare against the same.
        expected = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        assert f"repo_path='{expected}'" in msg

    def test_repo_path_with_single_quote_is_escaped(self):
        """A path containing a single quote must produce a syntactically valid
        Python string literal (the agent reproduces the call verbatim), not a
        broken one like repo_path='/a'b'. repr() handles the escaping."""
        weird = "/tmp/it's a repo"
        msg = hook_core.build_system_message("git commit -m 'x'", repo_path=weird)
        # The injected literal must round-trip back to the original path.
        assert f"repo_path={weird!r}" in msg
        # And it must be parseable as a real Python string literal.
        import ast

        literal = msg.split("repo_path=", 1)[1].split(")", 1)[0]
        assert ast.literal_eval(literal) == weird


class TestCrossAdapterInterop:
    """Verify .scan-pass written once is accepted by all adapter scripts."""

    def test_scan_pass_accepted_by_all_adapters(self, tmp_path):
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
        test_file = tmp_path / "file.py"
        test_file.write_text("x = 1")
        subprocess.run(["git", "add", "file.py"], cwd=str(tmp_path), capture_output=True)
        diff_result = subprocess.run(
            ["git", "diff", "--cached", "--no-color", "--no-ext-diff"],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
        )
        staged_hash = hashlib.sha256(diff_result.stdout.encode()).hexdigest()
        # All adapters run with cwd=tmp_path and resolve the scan-pass via git.
        scan_pass_path(tmp_path).write_text(staged_hash)

        hooks_dir = os.path.join(os.path.dirname(__file__), "..")
        adapters = [
            ("pre_commit_scan.py", {"tool_input": {"command": "git commit -m 'x'"}}),
            (
                "gemini_pre_tool.py",
                {"tool_name": "run_shell_command", "tool_input": {"command": "git commit -m 'x'"}},
            ),
            (
                "codex_pre_tool.py",
                {"tool_name": "shell", "tool_input": {"command": "git commit -m 'x'"}},
            ),
            (
                "cursor_pre_tool.py",
                {"tool_name": "terminal", "tool_input": {"command": "git commit -m 'x'"}},
            ),
            (
                "copilot_pre_tool.py",
                {"toolName": "bash", "toolArgs": {"command": "git commit -m 'x'"}},
            ),
            (
                "cline_pre_tool.py",
                {"tool": {"name": "execute_command", "input": {"command": "git commit -m 'x'"}}},
            ),
        ]

        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)

        for script, payload in adapters:
            result = subprocess.run(
                [sys.executable, os.path.join(hooks_dir, script)],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
                cwd=str(tmp_path),
            )
            assert result.returncode == 0, f"{script} returned {result.returncode}: {result.stderr}"
