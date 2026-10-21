"""Windows forms for the commit gate and the scan-pass forgery guards.

Covers `git.exe` / `gh.exe` / quoted-path binaries, backslash paths, cmd and
PowerShell write verbs, and the NTFS aliases of the scan-pass filename. Commands
are fed straight to hook_core, so these run on any OS.
"""

import os
import sys

import pytest

_hooks_dir = os.path.join(os.path.dirname(__file__), "..")
if _hooks_dir not in sys.path:
    sys.path.insert(0, _hooks_dir)

import hook_core

# ---------------------------------------------------------------------------
# A. shipping commands behind a Windows binary name
# ---------------------------------------------------------------------------
_SHIPPING = [
    'git.exe commit -m "x"',
    'GIT.EXE commit -m "x"',
    "Git.Exe push origin main",
    "gh.exe pr create --fill",
    "GH.EXE pr create --fill",
    '/usr/bin/git commit -m "x"',
    '"C:/Program Files/Git/cmd/git.exe" commit -m "x"',
    "'C:/Program Files/Git/cmd/git.exe' push",
    'C:/Git/cmd/git.exe commit -m "x"',
    '"C:\\Program Files\\Git\\cmd\\git.exe" commit -m "x"',
    '& "C:\\Program Files\\Git\\cmd\\git.exe" commit -m "x"',
    '"git" commit -m "x"',
    '"git.exe" commit -m "x"',
    'git.exe -C repo commit -m "x"',
    'git add . ; git.exe commit -m "x"',
    "cd repo && GIT.EXE push",
    '"C:\\Program Files\\GitHub CLI\\gh.exe" pr create --fill',
]


@pytest.mark.parametrize("cmd", _SHIPPING)
def test_windows_shipping_commands_detected(cmd):
    assert hook_core._is_shipping_command(cmd)


@pytest.mark.parametrize(
    ("cmd", "is_commit"),
    [
        ('git.exe commit -m "x"', True),
        ('GIT.EXE commit -m "x"', True),
        ('"C:/Program Files/Git/cmd/git.exe" commit -m "x"', True),
        ("git.exe push", False),
        ("gh.exe pr create --fill", False),
    ],
)
def test_windows_commit_vs_push(cmd, is_commit):
    assert hook_core._is_commit(cmd) is is_commit
    assert hook_core._is_push_or_pr(cmd) is (not is_commit)


@pytest.mark.parametrize("cmd", _SHIPPING)
def test_windows_shipping_denied_without_scan_pass(cmd, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # a real (empty) git repo: no scan-pass
    assert hook_core.check_gate(cmd).decision == "deny"


@pytest.mark.parametrize(
    "cmd",
    [
        "git.exe commit -am x",
        "git.exe commit --all -m x",
        "GIT.EXE commit -m x -- file.py",
        "git.exe add -A && git.exe commit -m x",
        "git.exe add -A; GIT.EXE commit -m x",
        "$env:GIT_INDEX_FILE = 'other'; git.exe commit -m x",
        "$env:GIT_DIR = 'other'; git commit -m x",
        '"C:/Program Files/Git/cmd/git.exe" commit -a -m x',
        "eval 'git.exe commit -a'",
    ],
)
def test_windows_index_changing_commit_denied(cmd, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert hook_core._index_changing_commit(cmd)


def test_windows_plain_commit_is_not_index_changing():
    assert hook_core._index_changing_commit('git.exe commit -m "x"') == ""
    assert hook_core._index_changing_commit('"C:/Program Files/Git/cmd/git.exe" commit -m x') == ""


@pytest.mark.parametrize(
    "cmd",
    [
        "git.exe status",
        "git.exe log --oneline",
        "gh.exe pr view 3",
        "mygit.exe commit",  # different binary
        "echo git.exe",
        'echo "git.exe commit"',
    ],
)
def test_windows_non_shipping_not_flagged(cmd):
    assert not hook_core._is_shipping_command(cmd)


# ---------------------------------------------------------------------------
# B. forgery: Windows write forms (Bash tool under Git Bash, PowerShell tool)
# ---------------------------------------------------------------------------
_FORGERY = [
    'echo deadbeef > ".git\\armis-scan-pass"',
    "echo deadbeef > '.git\\armis-scan-pass'",
    "echo deadbeef > .git\\\\armis-scan-pass",
    "echo deadbeef > C:/Users/dev/repo/.git/armis-scan-pass",
    'echo deadbeef > "C:\\Users\\John Doe\\repo\\.git\\armis-scan-pass"',
    "echo deadbeef > .git/armis-scan-pass.",
    'echo deadbeef > ".git/armis-scan-pass::$DATA"',
    'echo deadbeef > "armis-scan-pass"',
    'cmd //c "echo deadbeef> .git\\armis-scan-pass"',
    "cmd //c copy NUL .git\\armis-scan-pass",
    "cmd.exe /c copy NUL .git\\armis-scan-pass",
    'powershell -NoProfile -Command "Set-Content -Path .git\\armis-scan-pass -Value deadbeef"',
    "pwsh -c \"'x' | Out-File .git/armis-scan-pass\"",
    "py -3 -c \"open('.git/armis-scan-pass','w').write('x')\"",
    # PowerShell tool
    "Set-Content -Path .git\\armis-scan-pass -Value deadbeef",
    "set-content .git\\armis-scan-pass deadbeef",
    "'x' | Out-File -FilePath .git\\armis-scan-pass",
    "Add-Content .git\\armis-scan-pass x",
    "New-Item -Path .git\\armis-scan-pass -Value x -Force",
    "Copy-Item $h .git\\armis-scan-pass",
    "Move-Item $h .git\\armis-scan-pass",
    "copy $h .git\\armis-scan-pass",
    "Get-Date; copy $h .git\\armis-scan-pass",
    "[IO.File]::WriteAllText('.git\\armis-scan-pass', 'x')",
    "[System.IO.File]::WriteAllText(\".git\\armis-scan-pass\", 'x')",
    "$f = '.git\\armis-scan-pass'; Set-Content $f x",
    '$f = ".git\\armis-scan-pass"',
    "'x' > .git\\armis-scan-pass",
    "'x' >> .git\\armis-scan-pass",
    # NTFS aliases of the name
    "echo x > .git/ARMIS-~1",
    "echo x > .git\\SCAN-P~1",
]


@pytest.mark.parametrize("cmd", _FORGERY)
def test_windows_forgery_denied(cmd):
    assert hook_core._is_scan_pass_write_bash(cmd), cmd
    assert hook_core.check_gate(cmd).decision == "deny"


@pytest.mark.parametrize(
    "cmd",
    [
        "Get-Content .git\\armis-scan-pass",
        "type .git\\armis-scan-pass",
        "Remove-Item .git\\armis-scan-pass",
        "del .git\\armis-scan-pass",
        "Test-Path .git\\armis-scan-pass",
        "Select-String armis-scan-pass README.md",
        'git commit -m "copy armis-scan-pass handling"',
        'git commit -m "move armis-scan-pass into .git"',
        "cat app.py .git/armis-scan-pass",
        "pytest -k armis-scan-pass",
        "echo copy armis-scan-pass",
        "$x = 1",
    ],
)
def test_windows_mentions_still_allowed(cmd):
    assert not hook_core._is_scan_pass_write_bash(cmd), cmd


@pytest.mark.parametrize(
    "path",
    [
        ".git/armis-scan-pass.",  # Win32 strips trailing dots
        ".git/armis-scan-pass...",
        ".git/armis-scan-pass ",  # and spaces
        ".git/armis-scan-pass. .",
        ".git/armis-scan-pass::$DATA",  # default data stream
        ".git/armis-scan-pass:stream",
        ".git/armis-scan-pass:stream:$DATA",
        ".git\\ARMIS-SCAN-PASS",
        "C:\\repo\\.git\\Armis-Scan-Pass.",
        ".git/ARMIS-~1",  # 8.3 short name
        ".git/armis-~2",
        ".git\\SCAN-P~1",
        "C:\\repo\\.git\\.SCAN-PASS::$DATA",
    ],
)
def test_ntfs_aliases_of_scan_pass_file_blocked(path):
    assert hook_core.is_scan_pass_file(path)


@pytest.mark.parametrize(
    "path",
    [
        ".git/armis-scan-passport",
        ".git/armis-scan-pass.bak",
        ".git/armis-scan-pass.txt",
        "armis-~x",
        "C:\\repo\\app.py",
        "notes:armis-scan-pass-doc",
    ],
)
def test_unrelated_names_not_blocked(path):
    assert not hook_core.is_scan_pass_file(path)
