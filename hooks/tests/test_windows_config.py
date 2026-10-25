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
from conftest import git_bash  # noqa: E402


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
    # A double-quoted `$s = "<path>"` lost its quotes and ran the .py by file association.
    assert "$s = '${CLAUDE_PLUGIN_ROOT}/hooks/pre_commit_scan.py';" in cmd


def test_powershell_hook_probes_every_path_match():
    # The Microsoft Store python/python3 stubs resolve by name but exit non-zero.
    cmd = _by_matcher("PowerShell")["command"]
    assert "foreach ($d in $env:Path -split ';')" in cmd
    # Relative PATH entries (".") would run a python.exe from the user's repo.
    assert "[IO.Path]::IsPathRooted($d)" in cmd
    # Windows PowerShell 5.1 strips embedded double quotes from a native command's argument.
    assert '"' not in cmd
    assert cmd.index("-c 0 *> $null") < cmd.index("$input |")
    assert cmd.index("'py'") < cmd.index("'python'") < cmd.index("'python3'")


def test_mcp_json_launches_extensionless_run_on_every_os():
    with open(os.path.join(_ROOT, ".mcp.json")) as f:
        command = json.load(f)["scanner"]["command"]
    assert command == "${CLAUDE_PLUGIN_ROOT}/run"
    # Windows resolves "run" to run.cmd (PATHEXT); POSIX executes the sh script.
    assert os.access(os.path.join(_ROOT, "run"), os.X_OK)
    with open(os.path.join(_ROOT, "run")) as f:
        assert 'exec "$(dirname "$0")/run.sh"' in f.read()
    with open(os.path.join(_ROOT, "run.cmd")) as f:
        cmd = f.read()
    assert "run.sh" in cmd and "bash.exe" in cmd
    assert "CLAUDE_CODE_GIT_BASH_PATH" in cmd
    # run.sh's dirname "$0" splits on "/" only.
    assert '"%ARMIS_RUN_SH:\\=/%"' in cmd


def _commands(node):
    """Every hook command string in a manifest, whatever the client's key name."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("command", "bash") and isinstance(value, str):
                yield value
            else:
                yield from _commands(value)
    elif isinstance(node, list):
        for item in node:
            yield from _commands(item)


# Quoted, so a plugin path with a space (C:/Users/John Smith/...) stays one argument.
_LAUNCHER = re.compile(
    r'\. "(?P<root>[^"]+)/hooks/find-python\.sh" && run_hook "(?P=root)/hooks/(?P<script>\w+\.py)"'
)


@pytest.mark.parametrize("matcher", ["Bash", "Write", "Edit"])
def test_bash_form_hooks_go_through_the_launcher(matcher):
    hook = _by_matcher(matcher)
    m = _LAUNCHER.fullmatch(hook["command"])
    assert m, hook["command"]
    assert m["root"] == "${CLAUDE_PLUGIN_ROOT}"
    assert "shell" not in hook


@pytest.mark.parametrize("path", _TEMPLATES, ids=os.path.basename)
def test_client_templates_go_through_the_launcher(path):
    with open(path) as f:
        commands = list(_commands(json.load(f)))
    assert commands, path
    for cmd in commands:
        m = _LAUNCHER.fullmatch(cmd)
        assert m, cmd
        assert os.path.isfile(os.path.join(_ROOT, "hooks", m["script"])), m["script"]


@pytest.mark.skipif(git_bash() is None, reason="needs bash")
@pytest.mark.parametrize("matcher", ["Bash", "Write"])
def test_manifest_command_runs_from_a_path_with_a_space(tmp_path, matcher):
    root = tmp_path / "with space"
    shutil.copytree(
        os.path.join(_ROOT, "hooks"), root / "hooks", ignore=shutil.ignore_patterns("tests")
    )
    for name in os.listdir(_ROOT):
        if name.endswith(".py"):
            shutil.copy(os.path.join(_ROOT, name), root / name)
    cmd = _by_matcher(matcher)["command"].replace("${CLAUDE_PLUGIN_ROOT}", str(root))
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=str(repo), check=True)
    pass_file = repo / ".git" / "armis-scan-pass"
    if matcher == "Bash":
        payload = {"tool_name": "Bash", "tool_input": {"command": f"echo x > {pass_file}"}}
    else:
        payload = {"tool_name": "Write", "tool_input": {"file_path": str(pass_file)}}
    r = subprocess.run(
        [git_bash(), "-c", cmd],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=20,
        cwd=str(repo),
    )
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert json.loads(r.stderr)["hookSpecificOutput"]["permissionDecision"] == "deny"


# ---------------------------------------------------------------------------
# CRLF checkouts (Git for Windows defaults to core.autocrlf=true)
# ---------------------------------------------------------------------------
@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
@pytest.mark.parametrize("path", ["run.sh", "run", "git-hooks/pre-commit", "hooks/find-python.sh"])
def test_gitattributes_pins_bash_scripts_to_lf(path):
    r = subprocess.run(
        ["git", "check-attr", "eol", "--", path],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert r.stdout.strip().endswith("eol: lf"), r.stdout


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
def _fake_exe(directory, name):
    directory.mkdir(parents=True, exist_ok=True)
    exe = directory / (name + (".exe" if sys.platform == "win32" else ""))
    exe.write_text("")
    exe.chmod(0o755)
    return str(exe)


def _report_names(report, expected_name, expected_path):
    prefix = f"Hook interpreter: {expected_name} ("
    assert report.startswith(prefix), report
    assert os.path.normcase(report[len(prefix) : -1]) == os.path.normcase(expected_path)


def test_hook_python_report(monkeypatch, tmp_path):
    sys.path.insert(0, _ROOT)
    import server

    monkeypatch.setattr(
        server.subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 0)
    )
    py = _fake_exe(tmp_path / "launcher", "py")
    monkeypatch.setenv("PATH", str(tmp_path / "launcher"))
    _report_names(server._hook_python_report(), "py", py)
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert "NONE FOUND" in server._hook_python_report()
    assert "NOT gated" in server._hook_python_report()


def test_hook_python_report_skips_store_stub_earlier_on_path(monkeypatch, tmp_path):
    sys.path.insert(0, _ROOT)
    import server

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 49 if "WindowsApps" in cmd[0] else 0)

    stubs, real = tmp_path / "WindowsApps", tmp_path / "Python312"
    _fake_exe(stubs, "python3")
    _fake_exe(stubs, "python")
    python3 = _fake_exe(real, "python3")
    monkeypatch.setattr(server.subprocess, "run", fake_run)
    monkeypatch.setenv("PATH", os.pathsep.join([str(stubs), str(real)]))
    _report_names(server._hook_python_report(), "python3", python3)
