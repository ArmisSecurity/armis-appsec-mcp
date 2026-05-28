"""Tests for pre_commit_scan.py PreToolUse hook."""

import hashlib
import json
import subprocess
import uuid

import pytest


# ---------------------------------------------------------------------------
# Shipping command detection — should BLOCK
# ---------------------------------------------------------------------------
class TestShippingDetection:
    """Commands that should trigger the security gate (exit 2 + deny on stderr)."""

    @pytest.mark.parametrize(
        "cmd",
        [
            "git commit -m 'feat: add auth'",
            'git commit -m "fix: patch vuln"',
            "git commit --amend",
            "git commit --amend --no-edit",
            "git push",
            "git push origin main",
            "git push -u origin feat/branch",
            "gh pr create --title 'My PR'",
            'gh pr create --title "PR" --body "desc"',
        ],
    )
    def test_simple_shipping_commands_block(self, run_hook, cmd):
        stdout, stderr, rc = run_hook(cmd)
        assert rc == 2, f"Expected exit 2 for '{cmd}', got {rc}"
        assert stderr, f"Expected stderr JSON for '{cmd}'"
        data = json.loads(stderr)
        assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "Security scan required" in data["systemMessage"]

    @pytest.mark.parametrize(
        "cmd",
        [
            "git add . && git commit -m 'msg'",
            "git commit -m 'msg' && git push",
            "git add -A && git commit -m 'msg' && git push origin main",
            "echo done; git push",
            "echo done || git commit -m 'msg'",
        ],
    )
    def test_compound_shipping_commands_block(self, run_hook, cmd):
        stdout, stderr, rc = run_hook(cmd)
        assert rc == 2, f"Expected exit 2 for compound '{cmd}', got {rc}"


# ---------------------------------------------------------------------------
# Non-shipping commands — should ALLOW
# ---------------------------------------------------------------------------
class TestNonShippingCommands:
    """Commands that should pass through without blocking (exit 0)."""

    @pytest.mark.parametrize(
        "cmd",
        [
            "git status",
            "git diff",
            "git diff --cached",
            "git log --oneline -10",
            "git branch",
            "git checkout -b new-branch",
            "git add .",
            "git stash",
            "git fetch origin",
            "ls -la",
            "python app.py",
            "npm test",
            "cat README.md",
            "grep -r 'TODO' .",
        ],
    )
    def test_non_shipping_commands_allow(self, run_hook, cmd):
        stdout, stderr, rc = run_hook(cmd)
        assert rc == 0, f"Expected exit 0 for '{cmd}', got {rc}"
        assert json.loads(stdout) == {}
        assert stderr == ""

    def test_empty_command_allows(self, run_hook):
        stdout, stderr, rc = run_hook("")
        assert rc == 0

    def test_git_commit_inside_echo_is_not_false_positive(self, run_hook):
        """echo 'git commit' > log.txt — correctly NOT matched as shipping."""
        stdout, stderr, rc = run_hook('echo "git commit" > log.txt')
        assert rc == 0


# ---------------------------------------------------------------------------
# .scan-pass mechanism (content-hash based)
# ---------------------------------------------------------------------------


def _init_git_repo(path, unique=False):
    """Create a minimal git repo with one staged file, return the staged diff hash.

    When unique=True, stages randomized content so the hash cannot accidentally
    collide with .scan-pass files from other test runs or development usage.
    """
    subprocess.run(["git", "init"], cwd=str(path), capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=str(path),
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=str(path),
        capture_output=True,
    )
    # Initial commit so HEAD exists
    (path / "init.txt").write_text("init")
    subprocess.run(["git", "add", "init.txt"], cwd=str(path), capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=str(path),
        capture_output=True,
    )
    # Stage a test file — unique content prevents hash collisions with other .scan-pass files
    content = f"# {uuid.uuid4()}\nprint('hello')\n" if unique else "print('hello')\n"
    (path / "test.py").write_text(content)
    subprocess.run(["git", "add", "test.py"], cwd=str(path), capture_output=True)
    # Compute the staged diff hash
    result = subprocess.run(
        ["git", "diff", "--cached", "--no-color"],
        cwd=str(path),
        capture_output=True,
        text=True,
    )
    return hashlib.sha256(result.stdout.encode()).hexdigest()


class TestScanPass:
    """Content-hash .scan-pass: allows commit only when hash matches staged diff."""

    def test_matching_hash_allows_commit(self, run_hook, tmp_path):
        staged_hash = _init_git_repo(tmp_path)
        scan_pass = tmp_path / ".scan-pass"
        scan_pass.write_text(staged_hash)

        stdout, stderr, rc = run_hook("git commit -m 'msg'")
        assert rc == 0, "Matching hash should allow commit"
        assert json.loads(stdout) == {}

    def test_mismatched_hash_blocks_commit(self, run_hook, tmp_path):
        _init_git_repo(tmp_path)
        scan_pass = tmp_path / ".scan-pass"
        scan_pass.write_text("0000000000000000000000000000000000000000000000000000000000000000")

        stdout, stderr, rc = run_hook("git commit -m 'msg'")
        assert rc == 2, "Mismatched hash should block commit"

    def test_missing_scan_pass_blocks(self, run_hook, tmp_path):
        _init_git_repo(tmp_path)
        stdout, stderr, rc = run_hook("git commit -m 'msg'")
        assert rc == 2, "Missing .scan-pass should block"

    def test_empty_scan_pass_blocks(self, run_hook, tmp_path):
        _init_git_repo(tmp_path)
        scan_pass = tmp_path / ".scan-pass"
        scan_pass.write_text("")

        stdout, stderr, rc = run_hook("git commit -m 'msg'")
        assert rc == 2, "Empty .scan-pass should block (fail-closed)"

    def test_push_with_scan_pass_allows(self, run_hook, tmp_path):
        """Push checks file existence only (commit already enforced hash)."""
        _init_git_repo(tmp_path)  # CWE-73: path must be in git repo
        scan_pass = tmp_path / ".scan-pass"
        scan_pass.write_text("any-content-works-for-push")

        stdout, stderr, rc = run_hook("git push origin main")
        assert rc == 0, ".scan-pass exists should allow push"

    def test_push_without_scan_pass_blocks(self, run_hook, tmp_path):
        stdout, stderr, rc = run_hook("git push origin main")
        assert rc == 2, "Missing .scan-pass should block push"

    def test_pr_create_with_scan_pass_allows(self, run_hook, tmp_path):
        _init_git_repo(tmp_path)  # CWE-73: path must be in git repo
        scan_pass = tmp_path / ".scan-pass"
        scan_pass.write_text("any-content-works-for-pr")

        stdout, stderr, rc = run_hook("gh pr create --title 'PR'")
        assert rc == 0, ".scan-pass exists should allow PR create"

    def test_new_staged_changes_after_scan_blocks(self, run_hook, tmp_path):
        """Stage new code after scan -> hash mismatch -> block."""
        old_hash = _init_git_repo(tmp_path)
        scan_pass = tmp_path / ".scan-pass"
        scan_pass.write_text(old_hash)

        # Stage additional file (changes the staged diff hash)
        (tmp_path / "new_file.py").write_text("import os\n")
        subprocess.run(["git", "add", "new_file.py"], cwd=str(tmp_path), capture_output=True)

        stdout, stderr, rc = run_hook("git commit -m 'msg'")
        assert rc == 2, "New staged changes should invalidate .scan-pass"

    def test_scan_pass_does_not_affect_non_shipping(self, run_hook, tmp_path):
        """Non-shipping commands should allow regardless of .scan-pass state."""
        stdout, stderr, rc = run_hook("git status")
        assert rc == 0


# ---------------------------------------------------------------------------
# Command-specific systemMessage
# ---------------------------------------------------------------------------
class TestCommandSpecificMessages:
    """Different commands should get different scan instructions."""

    def test_commit_gets_staged_scan(self, run_hook):
        stdout, stderr, rc = run_hook("git commit -m 'msg'")
        assert rc == 2
        data = json.loads(stderr)
        assert "scan_diff(staged=True)" in data["systemMessage"]

    def test_commit_a_gets_unstaged_scan(self, run_hook):
        stdout, stderr, rc = run_hook("git commit -a -m 'msg'")
        assert rc == 2
        data = json.loads(stderr)
        assert "scan_diff()" in data["systemMessage"]
        assert "staged=True" not in data["systemMessage"]

    def test_commit_all_flag_gets_unstaged_scan(self, run_hook):
        stdout, stderr, rc = run_hook("git commit --all -m 'msg'")
        assert rc == 2
        data = json.loads(stderr)
        assert "scan_diff()" in data["systemMessage"]
        assert "staged=True" not in data["systemMessage"]

    def test_push_gets_ref_scan(self, run_hook):
        stdout, stderr, rc = run_hook("git push")
        assert rc == 2
        data = json.loads(stderr)
        assert "scan_diff(ref='origin/HEAD')" in data["systemMessage"]

    def test_push_origin_main_gets_ref_scan(self, run_hook):
        stdout, stderr, rc = run_hook("git push origin main")
        assert rc == 2
        data = json.loads(stderr)
        assert "scan_diff(ref='origin/HEAD')" in data["systemMessage"]

    def test_pr_create_gets_ref_scan(self, run_hook):
        stdout, stderr, rc = run_hook("gh pr create --title 'PR'")
        assert rc == 2
        data = json.loads(stderr)
        assert "scan_diff(ref='origin/HEAD')" in data["systemMessage"]

    def test_system_message_has_calm_language(self, run_hook):
        stdout, stderr, rc = run_hook("git commit -m 'msg'")
        data = json.loads(stderr)
        assert "SECURITY GATE" not in data["systemMessage"]
        assert "YOUR VERY NEXT TOOL CALL" not in data["systemMessage"]
        assert "Security scan required" in data["systemMessage"]

    def test_system_message_mentions_approve_findings(self, run_hook):
        stdout, stderr, rc = run_hook("git commit -m 'msg'")
        data = json.loads(stderr)
        assert "approve_findings" in data["systemMessage"]

    def test_system_message_warns_against_self_approval(self, run_hook):
        stdout, stderr, rc = run_hook("git commit -m 'msg'")
        data = json.loads(stderr)
        msg = data["systemMessage"]
        assert "Do NOT call approve_findings on your own" in msg


# ---------------------------------------------------------------------------
# Output format
# ---------------------------------------------------------------------------
class TestOutputFormat:
    """Verify the exact JSON structure for block and allow responses."""

    def test_block_output_format(self, run_hook):
        stdout, stderr, rc = run_hook("git commit -m 'msg'")
        assert rc == 2
        assert stdout == ""
        data = json.loads(stderr)
        assert "hookSpecificOutput" in data
        assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "systemMessage" in data

    def test_allow_output_format(self, run_hook):
        stdout, stderr, rc = run_hook("git status")
        assert rc == 0
        assert json.loads(stdout) == {}
        assert stderr == ""


# ---------------------------------------------------------------------------
# Fail-open
# ---------------------------------------------------------------------------
class TestFailOpen:
    """Hook bugs should never block the developer."""

    def test_invalid_json_stdin(self, run_hook_raw):
        result = run_hook_raw("not json at all")
        assert result.returncode == 0

    def test_empty_stdin(self, run_hook_raw):
        result = run_hook_raw("")
        assert result.returncode == 0

    def test_missing_tool_input_raw(self, run_hook_raw):
        result = run_hook_raw(json.dumps({"tool_name": "Bash"}))
        assert result.returncode == 0

    def test_missing_command_key(self, run_hook_raw):
        result = run_hook_raw(
            json.dumps({"tool_name": "Bash", "tool_input": {"file_path": "/tmp/x"}})
        )
        assert result.returncode == 0

    def test_non_bash_tool(self, run_hook):
        stdout, stderr, rc = run_hook("git commit -m 'msg'", tool_name="Write")
        assert rc == 2  # Hook doesn't filter by tool_name, matcher does


# ---------------------------------------------------------------------------
# Unit tests for helper functions
# ---------------------------------------------------------------------------
class TestHelpers:
    """Direct tests of detection functions."""

    def test_is_shipping_command(self, hook_module):
        assert hook_module._is_shipping_command("git commit -m 'msg'")
        assert hook_module._is_shipping_command("git push")
        assert hook_module._is_shipping_command("gh pr create --title 'PR'")
        assert not hook_module._is_shipping_command("git status")
        assert not hook_module._is_shipping_command("ls -la")

    def test_is_push_or_pr(self, hook_module):
        assert hook_module._is_push_or_pr("git push")
        assert hook_module._is_push_or_pr("gh pr create")
        assert not hook_module._is_push_or_pr("git commit -m 'msg'")

    def test_has_all_flag(self, hook_module):
        assert hook_module._has_all_flag("git commit -a -m 'msg'")
        assert hook_module._has_all_flag("git commit --all -m 'msg'")
        assert not hook_module._has_all_flag("git commit -m 'msg'")


# ---------------------------------------------------------------------------
# CWE-73: External Control of File Name or Path
# ---------------------------------------------------------------------------
class TestCWE73PluginRootValidation:
    """CWE-73 mitigation: CLAUDE_PLUGIN_ROOT must be within git repo bounds."""

    def test_plugin_root_within_repo_accepts(self, run_hook, tmp_path):
        """Valid path within git repo should be accepted."""
        _init_git_repo(tmp_path)
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        scan_pass = subdir / ".scan-pass"
        scan_pass.write_text("any-content")

        # Set CLAUDE_PLUGIN_ROOT to subdir within repo
        stdout, stderr, rc = run_hook("git push", env_override={"CLAUDE_PLUGIN_ROOT": str(subdir)})
        assert rc == 0, "Valid path within repo should allow push"

    def test_plugin_root_at_repo_root_accepts(self, run_hook, tmp_path):
        """CLAUDE_PLUGIN_ROOT at git repo root should be accepted."""
        _init_git_repo(tmp_path)
        scan_pass = tmp_path / ".scan-pass"
        scan_pass.write_text("any-content")

        stdout, stderr, rc = run_hook(
            "git push", env_override={"CLAUDE_PLUGIN_ROOT": str(tmp_path)}
        )
        assert rc == 0, "Repo root should be accepted"

    def test_plugin_root_outside_repo_rejects(self, run_hook, tmp_path):
        """Path outside git repo should be rejected (falls back to default)."""
        # Stage unique content so hash never matches any .scan-pass in fallback location
        _init_git_repo(tmp_path, unique=True)

        # Create attacker-controlled dir outside repo
        attacker_dir = tmp_path.parent / "attacker_controlled"
        attacker_dir.mkdir(exist_ok=True)
        fake_scan_pass = attacker_dir / ".scan-pass"
        fake_scan_pass.write_text("forged-bypass-token")

        # Try to bypass by pointing CLAUDE_PLUGIN_ROOT outside repo
        stdout, stderr, rc = run_hook(
            "git commit -m 'msg'", env_override={"CLAUDE_PLUGIN_ROOT": str(attacker_dir)}
        )
        # Should block: attacker path rejected (not in git repo), fallback's
        # .scan-pass (if any) has a different hash than our unique staged diff
        assert rc == 2, "Path outside repo should be rejected, causing block"
        data = json.loads(stderr)
        assert data["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_plugin_root_path_traversal_rejects(self, run_hook, tmp_path):
        """Path traversal attempts should be rejected."""
        _init_git_repo(tmp_path, unique=True)

        # Try path traversal to escape repo
        attacker_dir = tmp_path.parent / "escape"
        attacker_dir.mkdir(exist_ok=True)
        fake_scan_pass = attacker_dir / ".scan-pass"
        fake_scan_pass.write_text("forged")

        # Attempt path traversal (will be resolved by realpath)
        traversal = str(tmp_path / ".." / "escape")

        stdout, stderr, rc = run_hook(
            "git commit -m 'msg'", env_override={"CLAUDE_PLUGIN_ROOT": traversal}
        )
        assert rc == 2, "Path traversal should be rejected"

    def test_plugin_root_symlink_escape_rejects(self, run_hook, tmp_path):
        """Symlink pointing outside repo should be rejected."""
        _init_git_repo(tmp_path, unique=True)

        # Create attacker dir outside repo
        attacker_dir = tmp_path.parent / "attacker_symlink_target"
        attacker_dir.mkdir(exist_ok=True)
        fake_scan_pass = attacker_dir / ".scan-pass"
        fake_scan_pass.write_text("forged")

        # Create symlink inside repo pointing outside
        symlink_path = tmp_path / "evil_link"
        try:
            symlink_path.symlink_to(attacker_dir)
        except OSError:
            pytest.skip("Symlinks not supported on this platform")

        stdout, stderr, rc = run_hook(
            "git commit -m 'msg'", env_override={"CLAUDE_PLUGIN_ROOT": str(symlink_path)}
        )
        # realpath() resolves symlink to attacker_dir, which is outside repo
        assert rc == 2, "Symlink escape should be rejected"

    def test_plugin_root_nonexistent_path_falls_back(self, run_hook, tmp_path):
        """Nonexistent path should fall back to default."""
        _init_git_repo(tmp_path, unique=True)

        stdout, stderr, rc = run_hook(
            "git commit -m 'msg'",
            env_override={"CLAUDE_PLUGIN_ROOT": "/nonexistent/fake/path/12345"},
        )
        assert rc == 2, "Nonexistent path should fall back and block"

    def test_plugin_root_empty_string_falls_back_to_cwd_git_root(self, run_hook, tmp_path):
        """Empty CLAUDE_PLUGIN_ROOT should fall back to CWD's git root."""
        staged_hash = _init_git_repo(tmp_path, unique=True)
        scan_pass = tmp_path / ".scan-pass"
        scan_pass.write_text(staged_hash)

        stdout, stderr, rc = run_hook(
            "git commit -m 'msg'", env_override={"CLAUDE_PLUGIN_ROOT": ""}
        )
        # CWD is tmp_path (a git root) and .scan-pass hash matches → allow
        assert rc == 0, "Empty CLAUDE_PLUGIN_ROOT should use CWD git root"

    @pytest.mark.no_auto_git
    def test_find_git_root_helper(self, hook_module, tmp_path):
        """Unit test for _find_git_root helper."""
        # No git repo — remove auto-created .git from conftest
        git_dir = tmp_path / ".git"
        if git_dir.exists():
            git_dir.rmdir()
        assert hook_module._find_git_root(str(tmp_path)) is None

        # Create git repo
        _init_git_repo(tmp_path)
        subdir = tmp_path / "a" / "b" / "c"
        subdir.mkdir(parents=True)

        # Should find git root from deep subdirectory
        git_root = hook_module._find_git_root(str(subdir))
        assert git_root == str(tmp_path)
