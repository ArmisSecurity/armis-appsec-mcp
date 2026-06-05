"""Tests for hooks/cursor_pre_tool.py -- Cursor preToolUse adapter."""

import json
import os
import re
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import hook_core  # noqa: E402

HOOK_PATH = os.path.join(os.path.dirname(__file__), "..", "cursor_pre_tool.py")
CURSOR_HOOKS_JSON = os.path.join(
    os.path.dirname(__file__), "..", "..", "config-templates", "cursor.hooks.json"
)


@pytest.fixture
def run_cursor_hook(tmp_path):
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)

    def _run(tool_name="terminal", command="", file_path=None, env_override=None):
        tool_input = {}
        if command:
            tool_input["command"] = command
        if file_path:
            tool_input["file_path"] = file_path
        hook_input = {"tool_name": tool_name, "tool_input": tool_input}

        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)
        if env_override:
            env.update(env_override)

        result = subprocess.run(
            [sys.executable, HOOK_PATH],
            input=json.dumps(hook_input),
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
            cwd=str(tmp_path),
        )
        return result

    return _run


@pytest.fixture
def run_cursor_hook_raw(tmp_path):
    """Run the hook with an arbitrary JSON payload (e.g. Cursor's real flat
    beforeShellExecution shape, which has no tool_name/tool_input wrapper)."""
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)

    def _run(payload: dict, env_override=None):
        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)
        if env_override:
            env.update(env_override)
        result = subprocess.run(
            [sys.executable, HOOK_PATH],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
            cwd=str(tmp_path),
        )
        return result

    return _run


class TestBeforeShellExecutionFlatPayload:
    """Cursor's beforeShellExecution payload is FLAT
    ({command, cwd, sandbox, hook_event_name}), with no tool_name/tool_input.
    The adapter previously only ran the gate when tool_name was a shell name,
    so the real payload fell through to ALLOW for every shell command."""

    def test_flat_shipping_command_denies(self, run_cursor_hook_raw):
        payload = {
            "command": "git commit -m 'feat: x'",
            "cwd": "/project",
            "hook_event_name": "beforeShellExecution",
        }
        result = run_cursor_hook_raw(payload)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "deny"
        assert "Security scan required" in data["agent_message"]

    def test_flat_safe_command_allows(self, run_cursor_hook_raw):
        payload = {"command": "git status", "cwd": "/project"}
        result = run_cursor_hook_raw(payload)
        assert result.returncode == 0
        assert json.loads(result.stdout)["permission"] == "allow"

    @pytest.mark.parametrize(
        "cmd",
        [
            "echo deadbeef > .git/armis-scan-pass",  # redirect forgery
            "dd of=.git/armis-scan-pass",  # dd forgery
            "echo h > .scan-pass",  # legacy name
        ],
    )
    def test_flat_scan_pass_forgery_denied(self, run_cursor_hook_raw, cmd):
        # The whole point of #4: a scan-pass write via shell must reach the
        # adapter (the matcher includes `scan-pass`, so the write matches) and be
        # denied by check_gate's forgery guard.
        payload = {"command": cmd, "hook_event_name": "beforeShellExecution"}
        result = run_cursor_hook_raw(payload)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "deny"
        assert "BLOCKED" in data["agent_message"]


class TestShippingCommandsDeny:
    @pytest.mark.parametrize(
        "cmd",
        [
            "git commit -m 'feat: x'",
            "git push",
            "gh pr create --title 'PR'",
        ],
    )
    def test_shipping_commands_deny(self, run_cursor_hook, cmd):
        result = run_cursor_hook(tool_name="terminal", command=cmd)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "deny"
        assert "Security scan required" in data["agent_message"]


class TestNonShippingAllow:
    @pytest.mark.parametrize(
        "cmd",
        ["git status", "ls -la", "python app.py", "git diff"],
    )
    def test_non_shipping_allows(self, run_cursor_hook, cmd):
        result = run_cursor_hook(tool_name="terminal", command=cmd)
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "allow"


class TestWriteToolGuard:
    def test_write_to_scan_pass_denied(self, run_cursor_hook):
        result = run_cursor_hook(tool_name="Write", file_path="/project/.scan-pass")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "deny"
        assert "BLOCKED" in data["agent_message"]

    def test_write_to_normal_file_allowed(self, run_cursor_hook):
        result = run_cursor_hook(tool_name="Write", file_path="/project/app.py")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "allow"


class TestFailOpen:
    def test_empty_stdin(self, tmp_path):
        subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)
        result = subprocess.run(
            [sys.executable, HOOK_PATH],
            input="",
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
            cwd=str(tmp_path),
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "allow"

    def test_invalid_json(self, tmp_path):
        subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)
        result = subprocess.run(
            [sys.executable, HOOK_PATH],
            input="not json{{{",
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
            cwd=str(tmp_path),
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["permission"] == "allow"


class TestBeforeShellExecutionMatcherIsSuperset:
    """PR #19 review: the Cursor beforeShellExecution matcher was a catch-all
    (".*"), spawning python3 on EVERY shell command. We narrowed it to
    `\\bgit\\b|\\bgh\\b|scan-pass` to cut overhead. That narrowing is only SAFE
    if the matcher still fires on every command check_gate would deny — Cursor
    runs the matcher as a `contains`-regex over the full command string and only
    invokes the adapter on a match, so a command the matcher misses never reaches
    check_gate's forgery/shipping logic. These tests are the guardrail: they read
    the matcher from the shipped template and prove it is a strict SUPERSET of the
    gate's deny set. If someone narrows the matcher further and opens a hole, this
    fails. (A false POSITIVE just costs a fast `allow`; a false NEGATIVE is a
    bypass — so we assert superset, never equality.)"""

    @staticmethod
    def _matcher():
        with open(CURSOR_HOOKS_JSON) as f:
            cfg = json.load(f)
        pattern = cfg["hooks"]["beforeShellExecution"][0]["matcher"]
        return re.compile(pattern)

    def test_matcher_is_not_catch_all(self):
        # The whole point of the change: it must NOT be ".*" anymore.
        with open(CURSOR_HOOKS_JSON) as f:
            cfg = json.load(f)
        assert cfg["hooks"]["beforeShellExecution"][0]["matcher"] != ".*"

    # Every shipping form + forgery vector the gate cares about. Mirrors the
    # corpora in test_hook_core.py so the two stay in lockstep.
    @pytest.mark.parametrize(
        "cmd",
        [
            # shipping (incl. wrapper/env/global-opt prefixes)
            "git commit -m x",
            "git push",
            "gh pr create",
            "echo hi\ngit commit -m x",
            "git -C /repo commit -m x",
            "git --git-dir /r/.git commit -m x",
            "git --work-tree /repo push",
            "(git commit -m x)",
            "$(git commit -m x)",
            "/usr/bin/git commit -m x",
            "env git commit -m x",
            "GIT_AUTHOR_DATE=x git commit -m x",
            "sudo -u root git commit -m x",
            "timeout 5 git commit -m x",
            "env -i git commit -m x",
            "env -u FOO git push",
            "sudo env -i git commit -m x",
            "gh --repo o/r pr create",
            "command gh pr create",
            "\\git commit -m x",
            "git\tcommit -m x",  # tab between binary and subcommand
            # forgery (every vector denied by _is_scan_pass_write_bash)
            "echo h > .git/armis-scan-pass",
            "echo h >> .git/armis-scan-pass",
            "echo h > .scan-pass",
            "echo h | tee .git/armis-scan-pass",
            "cp /tmp/x .git/armis-scan-pass",
            "dd of=.git/armis-scan-pass",
            "sed -i s/a/b/ .git/armis-scan-pass",
            "vim .git/armis-scan-pass",
            "F=.git/armis-scan-pass; cat $F",
            "echo h >| .git/armis-scan-pass",
            "echo x | sponge .git/armis-scan-pass",
        ],
    )
    def test_matcher_fires_on_every_gate_relevant_command(self, cmd):
        matcher = self._matcher()
        gate_relevant = hook_core._is_shipping_command(cmd) or hook_core._is_scan_pass_write_bash(
            cmd
        )
        # Sanity: each corpus entry must actually be something the gate denies,
        # else the superset assertion below is vacuous.
        assert gate_relevant, f"corpus drift: {cmd!r} is no longer gate-relevant"
        assert matcher.search(cmd), (
            f"MATCHER HOLE: Cursor would not invoke the adapter for {cmd!r}, "
            f"so check_gate never runs and the command bypasses the gate."
        )

    @pytest.mark.parametrize(
        "cmd",
        [
            "ls -la",
            "cd /project",
            "npm test",
            "npm run build",
            "cat README.md",
            "python app.py",
            "pytest -q",
            "make check",
            "mkdir -p foo",
            "echo hello world",
        ],
    )
    def test_matcher_skips_benign_commands(self, cmd):
        # The performance win: these common commands must NOT spawn python3.
        # (Defensive — if a benign command did match it would only cost a fast
        # `allow`, but the narrowing is pointless if it still fires on everything.)
        assert not self._matcher().search(cmd)
