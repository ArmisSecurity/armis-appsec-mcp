"""The commit gate must deny commits that record more than the scanned index.

The PreToolUse hook hashes the staged diff *before* the Bash command runs, so a
command that stages more (`git add -A && git commit`) or a commit that stages
working-tree content itself (`-a`, `-i`, `-o`, `-p`, pathspecs) would otherwise
commit code the scan never saw under a valid scan-pass.
"""

import hashlib
import subprocess
import time

import hook_core
import pytest
from conftest import scan_pass_path

_HEREDOC_MSG = (
    "git commit -m \"$(cat <<'EOF'\n"
    'Fix "quoted phrase" handling (and parens)\n'
    "\n"
    "Don't break on apostrophes; or -a flags in the body.\n"
    "EOF\n"
    ')"'
)


class TestIndexChangingCommit:
    @pytest.mark.parametrize(
        "cmd",
        [
            "git commit -m 'x'",
            'git commit -m "fix: patch vuln"',
            "git commit --amend",
            "git commit --amend --no-edit",
            "git commit -qm x",
            "git commit -sS -m x",
            "git commit --message=x --author='A <a@b.c>'",
            "git commit -m x --trailer 'Co-authored-by: A <a@b.c>'",
            "git -C /repo commit -m x",
            "git -c user.name=x --no-pager commit -m x",
            "cd /repo && git commit -m x",
            "git commit -m x 2>&1 | tail -5",
            "git commit -m x >/dev/null",
            "git commit -m x # -a in a comment",
            "git commit -m x && git push",
            "git commit -F - <<'EOF'\nbody mentions -a and file.py\nEOF",
            "git commit -m x -- ",
            "GIT_AUTHOR_NAME='A B' git commit -m x",
            "/usr/bin/git commit -m x",
            _HEREDOC_MSG,
        ],
    )
    def test_index_as_scanned_is_allowed(self, cmd):
        assert hook_core._index_changing_commit(cmd) == ""

    @pytest.mark.parametrize(
        "cmd",
        [
            # staging in the same command runs after the gate hashed the index
            "git add -A && git commit -m x",
            "git add . && git commit -m x && git push",
            "git -C /repo add . ; git commit -m x",
            "git stash pop; git commit -m x",
            "git checkout other -- f.py && git commit -m x",
            "git commit -m x\ngit add .",
            'git commit -m "$(git add -A; echo msg)"',
            "git stage -A && git commit -m x",  # `stage` is a builtin synonym for add
            "git submodule add https://example.com/r.git r && git commit -m x",
            # env vars that point the commit at an index the gate never hashed
            "GIT_INDEX_FILE=/tmp/idx git commit -m x",
            "export GIT_INDEX_FILE=/tmp/idx; git commit -m x",
            "env GIT_DIR=/other/.git git commit -m x",
            # commit stages working-tree content itself
            "git commit -a -m x",
            "git commit -am x",
            "git commit -qam x",
            "git commit --all -m x",
            "git commit --al -m x",  # git accepts unambiguous abbreviations
            "git commit -i -m x f.py",
            "git commit --include -m x",
            "git commit -o -m x f.py",
            "git commit --only -m x",
            "git commit -p",
            "git commit --patch",
            "git commit --interactive",
            "git commit --pathspec-from-file=list.txt -m x",
            # pathspecs
            "git commit -m x f.py",
            "git commit -m x -- f.py",
            "git commit f.py -m x",
            "git commit -m x '|'",  # a quoted operator is a pathspec, not a pipe
            # can't see the commit's argv → fail closed
            "eval 'git commit -a -m x'",
            "git commit -m 'unterminated",
            'git commit -m "$(unterminated',
        ],
    )
    def test_index_changing_commit_is_flagged(self, cmd):
        assert hook_core._index_changing_commit(cmd) != ""

    @pytest.mark.parametrize(
        "make_input",
        [
            lambda: "git commit " + "-m x " * 4000,
            lambda: "git commit -m " + '"$(' * 5000,  # deep nesting must not recurse unbounded
            lambda: "git commit -m " + "$(" * 20000,
            lambda: "git commit -m " + "${" * 20000,
            lambda: "git commit -m x <<EOF\n" + "line\n" * 20000,
            lambda: "git " + "-x " * 4000 + "add && git commit -m x",
        ],
    )
    def test_linear_on_adversarial_input(self, make_input):
        # A timed-out hook fails open, so this must stay well under 10s.
        cmd = make_input()
        t0 = time.perf_counter()
        hook_core._index_changing_commit(cmd)
        assert time.perf_counter() - t0 < 1.0


def _repo_with_valid_pass(tmp_path, monkeypatch):
    for args in (
        ["init"],
        ["config", "user.email", "t@t.com"],
        ["config", "user.name", "T"],
    ):
        subprocess.run(["git", *args], cwd=tmp_path, capture_output=True, check=True)
    (tmp_path / "a.py").write_text("print('ok')\n")
    subprocess.run(["git", "add", "a.py"], cwd=tmp_path, capture_output=True, check=True)
    diff = subprocess.run(
        ["git", "diff", "--cached", "--no-color", "--no-ext-diff"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    monkeypatch.chdir(tmp_path)
    scan_pass_path(tmp_path).write_text(hashlib.sha256(diff.encode()).hexdigest())


class TestCheckGateIndexChanges:
    def test_plain_commit_with_valid_pass_allows(self, tmp_path, monkeypatch):
        _repo_with_valid_pass(tmp_path, monkeypatch)
        assert hook_core.check_gate("git commit -m x").decision == "allow"

    @pytest.mark.parametrize(
        "cmd",
        [
            "git add -A && git commit -m x",
            "git commit -a -m x",
            "git commit -m x a.py",
            "git add -A && git commit -m x && git push",
        ],
    )
    def test_index_changing_commit_denied_despite_valid_pass(self, tmp_path, monkeypatch, cmd):
        _repo_with_valid_pass(tmp_path, monkeypatch)
        result = hook_core.check_gate(cmd)
        assert result.decision == "deny"
        assert result.system_message.startswith("BLOCKED: this git commit")
        assert "scan_diff(staged=True" in result.system_message

    def test_commit_then_push_checks_commit_hash(self, tmp_path, monkeypatch):
        """A push in the same command used to short-circuit to the
        file-exists check, skipping the commit's hash match."""
        _repo_with_valid_pass(tmp_path, monkeypatch)
        (tmp_path / "b.py").write_text("import os; os.system(input())\n")
        subprocess.run(["git", "add", "b.py"], cwd=tmp_path, capture_output=True, check=True)
        result = hook_core.check_gate("git commit -m x && git push")
        assert result.decision == "deny"
        assert "scan_diff(staged=True" in result.system_message

    def test_commit_then_push_with_valid_pass_allows(self, tmp_path, monkeypatch):
        _repo_with_valid_pass(tmp_path, monkeypatch)
        assert hook_core.check_gate("git commit -m x && git push").decision == "allow"
