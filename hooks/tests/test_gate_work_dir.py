"""The gate checks the repo a shipping command acts on, not the hook's own CWD.

`git -C <repo> commit` records <repo>'s index, so a pass for the CWD repo must not
let it through, and a pass for <repo> must.
"""

import subprocess

import pytest
from conftest import scan_pass_path
from hook_core import check_gate

from hash_utils import compute_staged_hash, resolve_repo_toplevel


def _repo(path, staged=True):
    path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=path, check=True)
    if staged:
        (path / "a.py").write_text(f"print({path.name!r})\n")
        subprocess.run(["git", "add", "a.py"], cwd=path, check=True)
    return path


def _scan(repo):
    """What a clean scan_diff(staged=True, repo_path=repo) leaves behind."""
    scan_pass_path(repo).write_text(compute_staged_hash(str(repo)))


@pytest.fixture
def here(tmp_path, monkeypatch):
    repo = _repo(tmp_path / "here")
    monkeypatch.chdir(repo)
    return repo


@pytest.fixture
def other(tmp_path):
    return _repo(tmp_path / "other repo")


def test_pass_for_cwd_repo_does_not_cover_git_dash_c(here, other):
    _scan(here)
    r = check_gate(f'git -C "{other}" commit -m x')
    assert r.decision == "deny"
    # git's spelling of the path (forward slashes on Windows).
    assert f"repo_path={resolve_repo_toplevel(str(other))!r}" in r.system_message


def test_pass_for_target_repo_allows_git_dash_c(here, other):
    _scan(other)
    assert check_gate(f'git -C "{other}" commit -m x').decision == "allow"


def test_missing_dash_c_directory_denies(here, tmp_path):
    _scan(here)
    r = check_gate(f'git -C "{tmp_path / "nope"}" commit -m x')
    assert r.decision == "deny"
    assert "Security scan required" in r.system_message


def test_relative_dash_c_compose(here, other):
    _scan(other)
    cmd = f'git -C "{other.parent}" -C "{other.name}" commit -m x'
    assert check_gate(cmd).decision == "allow"


def test_cd_and_and_chain_is_followed(here, other):
    _scan(other)
    assert check_gate(f'cd "{other}" && git commit -m x').decision == "allow"
    _scan(here)
    other_pass = scan_pass_path(other)
    other_pass.unlink()
    assert check_gate(f'cd "{other}" && git commit -m x').decision == "deny"


def test_env_prefixed_git_still_resolves_its_repo(here, other):
    _scan(here)
    assert check_gate(f'GIT_AUTHOR_NAME=x git -C "{other}" commit -m x').decision == "deny"


@pytest.mark.parametrize(
    "template",
    [
        'cd "{d}"; git commit -m x',
        'cd "{d}" || git commit -m x',
        'true || cd "{d}" && git commit -m x',
        '(cd "{d}" && git commit -m x)',
        'builtin cd "{d}" && git commit -m x',
        'pushd "{d}" && git commit -m x',
        'Set-Location "{d}"; git commit -m x',
        'cd "$HOME" && git commit -m x',
        'git -C "$HOME" commit -m x',
    ],
)
def test_directory_changes_the_gate_cannot_follow_deny(here, other, template):
    _scan(here)
    _scan(other)
    r = check_gate(template.format(d=other))
    assert r.decision == "deny"
    assert "can't tell which repository" in r.system_message


@pytest.mark.parametrize("opt", ["--git-dir={d}/.git", "--work-tree={d}"])
def test_git_dir_and_work_tree_deny(here, other, opt):
    _scan(here)
    r = check_gate(f'git "{opt.format(d=other)}" commit -m x')
    assert r.decision == "deny"
    assert "different repository" in r.system_message


@pytest.mark.parametrize(
    "template",
    [
        'git -C "{d}" commit -m x',
        "git -C '{d}' commit -m x",
        'sudo -u root git -C "{d}" commit -m x',
        'env A=1 git "-C" "{d}" commit -m x',
    ],
)
def test_quoted_global_options_are_still_seen_as_a_commit(here, other, template):
    """The shipping regexes see text; a quoted option with a space hid the commit."""
    _scan(here)
    assert check_gate(template.format(d=other)).decision == "deny"


@pytest.mark.parametrize("cmd", ["echo git commit -m x", "git log --grep 'git commit'"])
def test_mentions_are_not_commits(here, cmd):
    assert check_gate(cmd).decision == "allow"


def test_cd_after_the_commit_does_not_matter(here, other):
    _scan(here)
    assert check_gate(f'git commit -m x && cd "{other}" && ls').decision == "allow"


def test_mentions_of_cd_in_a_message_are_not_directory_changes(here):
    _scan(here)
    assert check_gate('git commit -m "cd into the build dir"').decision == "allow"


def test_push_checks_the_target_repo(here, other):
    _scan(here)
    assert check_gate(f'git -C "{other}" push').decision == "deny"
    _scan(other)
    assert check_gate(f'git -C "{other}" push').decision == "allow"


def test_gh_pr_create_after_cd_checks_that_repo(here, other):
    _scan(here)
    assert check_gate(f'cd "{other}" && gh pr create --fill').decision == "deny"
    _scan(other)
    assert check_gate(f'cd "{other}" && gh pr create --fill').decision == "allow"
