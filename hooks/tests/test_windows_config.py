"""Hook manifests, config templates, and `make setup` for Windows machines.

- hooks/hooks.json must gate Claude Code's PowerShell tool as well as Bash.
- Every hook command must find a py-launcher-only Python install.
- `make setup CLIENT=codex|cline` has no MCP template and must still print hooks.
"""

import glob
import json
import os
import re
import shutil
import subprocess
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_HOOKS_JSON = os.path.join(_ROOT, "hooks", "hooks.json")
_TEMPLATES = sorted(glob.glob(os.path.join(_ROOT, "config-templates", "*.hooks.json")))
_PRE_COMMIT = os.path.join(_ROOT, "hooks", "pre_commit_scan.py")

sys.path.insert(0, os.path.join(_ROOT, "hooks"))
import hook_core  # noqa: E402


def _entries():
    with open(_HOOKS_JSON) as f:
        return json.load(f)["hooks"]["PreToolUse"]


def _by_matcher(matcher):
    (entry,) = [e for e in _entries() if e["matcher"] == matcher]
    (hook,) = entry["hooks"]
    return hook


def test_manifest_gates_both_shell_tools():
    matchers = {e["matcher"] for e in _entries()}
    assert {"Bash", "PowerShell", "Write", "Edit"} <= matchers


def test_powershell_hook_runs_under_powershell_with_stdout_protocol():
    hook = _by_matcher("PowerShell")
    assert hook["shell"] == "powershell"
    cmd = hook["command"]
    assert "pre_commit_scan.py" in cmd
    assert "--stdout-json" in cmd
    assert "$input" in cmd  # hook JSON arrives on stdin
    assert "${CLAUDE_PLUGIN_ROOT}" in cmd
    assert "command -v" not in cmd  # no bash-only syntax


@pytest.mark.parametrize("matcher", ["Bash", "Write", "Edit"])
def test_bash_form_hooks_fall_back_to_py_launcher(matcher):
    cmd = _by_matcher(matcher)["command"]
    assert cmd.index("python3") < cmd.index("elif command -v python ") < cmd.index("py -3")
    assert "shell" not in _by_matcher(matcher)


@pytest.mark.parametrize("path", _TEMPLATES, ids=os.path.basename)
def test_client_templates_fall_back_to_py_launcher(path):
    with open(path) as f:
        text = f.read()
    json.loads(text)
    commands = re.findall(r'"(?:command|bash)": "([^"]*command -v python3[^"]*)"', text)
    assert commands, path
    for cmd in commands:
        assert "elif command -v python " in cmd and "else py -3 " in cmd, cmd


def test_cursor_matcher_covers_windows_and_case_variants():
    with open(os.path.join(_ROOT, "config-templates", "cursor.hooks.json")) as f:
        cfg = json.load(f)
    matcher = re.compile(cfg["hooks"]["beforeShellExecution"][0]["matcher"])
    for cmd in [
        'GIT.EXE commit -m "x"',
        "gh.exe pr create",
        "echo x > .git/ARMIS-SCAN-PASS",
        "echo x > .git/ARMIS-~1",
        "echo x > .git\\SCAN-P~1",
    ]:
        assert matcher.search(cmd), cmd
    assert not matcher.search("npm test")


# ---------------------------------------------------------------------------
# --stdout-json protocol (used by the PowerShell hook)
# ---------------------------------------------------------------------------
def _run_pre_commit(command, cwd, *flags):
    return subprocess.run(
        [sys.executable, _PRE_COMMIT, *flags],
        input=json.dumps({"tool_name": "PowerShell", "tool_input": {"command": command}}),
        capture_output=True,
        text=True,
        timeout=20,
        cwd=str(cwd),
    )


def test_stdout_json_deny_exits_zero_with_decision_on_stdout(tmp_path):
    r = _run_pre_commit("Set-Content .git\\armis-scan-pass x", tmp_path, "--stdout-json")
    assert r.returncode == 0
    out = json.loads(r.stdout)
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert out["hookSpecificOutput"]["permissionDecisionReason"]
    assert r.stderr == ""


def test_stdout_json_allow_prints_empty_object(tmp_path):
    r = _run_pre_commit("Get-ChildItem", tmp_path, "--stdout-json")
    assert r.returncode == 0
    assert json.loads(r.stdout) == {}


def test_default_protocol_still_exit_2_stderr(tmp_path):
    r = _run_pre_commit("Set-Content .git\\armis-scan-pass x", tmp_path)
    assert r.returncode == 2
    assert json.loads(r.stderr)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_powershell_commit_without_pass_denied_via_stdout(tmp_path):
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)
    r = _run_pre_commit('git.exe commit -m "x"; Get-Date', tmp_path, "--stdout-json")
    assert r.returncode == 0
    assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_powershell_here_string_commit_is_parsed(tmp_path):
    """A PowerShell @"…"@ here-string message must not make the gate fail open."""
    cmd = 'git commit -m @"\nsubject\n\nbody\n"@'
    assert hook_core._is_commit(cmd)
    assert hook_core._index_changing_commit(cmd) == ""


# ---------------------------------------------------------------------------
# make setup for clients without an MCP template
# ---------------------------------------------------------------------------
@pytest.mark.skipif(shutil.which("make") is None, reason="needs make")
@pytest.mark.parametrize("client", ["codex", "cline"])
def test_make_setup_without_mcp_template_still_prints_hooks(client):
    r = subprocess.run(
        ["make", "-s", "setup", f"CLIENT={client}"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode == 0, r.stderr
    assert "=== Hook Config (commit gate) ===" in r.stdout
    assert "No MCP config template" in r.stderr
    tail = r.stdout.split("=== Hook Config (commit gate) ===", 1)[1].lstrip()
    json.JSONDecoder().raw_decode(tail)  # the hook JSON, then a trailing hint line


# ---------------------------------------------------------------------------
# hook interpreter surfaced in debug_config
# ---------------------------------------------------------------------------
def test_hook_python_report(monkeypatch):
    sys.path.insert(0, _ROOT)
    import server

    monkeypatch.setattr(server.shutil, "which", lambda n: "/x/py" if n == "py" else None)
    assert server._hook_python_report() == "Hook interpreter: py (/x/py)"
    monkeypatch.setattr(server.shutil, "which", lambda n: None)
    assert "NONE FOUND" in server._hook_python_report()
    assert "NOT gated" in server._hook_python_report()
