"""Tests for git-hooks/pre-commit shell script (portable git hook).

These are subprocess-based integration tests that exercise the shell hook
in a real temp git repo. The hook resolves PLUGIN_DIR from its own filesystem
location, so we replicate the directory structure exactly.
"""

import hashlib
import os
import subprocess
import sys

import pytest

# Actual plugin root — used to copy hash_utils.py
_PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_GIT_HOOK_SCRIPT = os.path.join(_PLUGIN_ROOT, "git-hooks", "pre-commit")


def _setup_plugin_structure(tmp_path):
    """Replicate the plugin directory layout so the hook can resolve PLUGIN_DIR.

    Structure:
        tmp_path/
          git-hooks/pre-commit     <- copy of the real hook
          hash_utils.py            <- copy of the real module
          .venv/bin/python         <- symlink to sys.executable
          .git/hooks/pre-commit    <- symlink to ../../git-hooks/pre-commit
    """
    # Create directories
    git_hooks_dir = tmp_path / "git-hooks"
    git_hooks_dir.mkdir()
    venv_bin = tmp_path / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir()

    # Copy the hook script
    with open(_GIT_HOOK_SCRIPT) as f:
        hook_src = f.read()
    hook_dest = git_hooks_dir / "pre-commit"
    hook_dest.write_text(hook_src)
    hook_dest.chmod(0o755)

    # Copy hash_utils.py
    with open(os.path.join(_PLUGIN_ROOT, "hash_utils.py")) as f:
        hash_utils_src = f.read()
    (tmp_path / "hash_utils.py").write_text(hash_utils_src)

    # Symlink python
    python_link = venv_bin / "python"
    python_link.symlink_to(sys.executable)

    # Symlink the hook (mimics `make install-hooks`)
    installed_hook = hooks_dir / "pre-commit"
    installed_hook.symlink_to("../../git-hooks/pre-commit")

    return installed_hook


def _init_git_repo(path):
    """Initialize a real git repo and stage a file. Returns staged diff hash."""
    subprocess.run(["git", "init"], cwd=str(path), capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=str(path),
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"], cwd=str(path), capture_output=True, check=True
    )

    # Initial commit so HEAD exists
    (path / "init.txt").write_text("init")
    subprocess.run(["git", "add", "init.txt"], cwd=str(path), capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(path), capture_output=True, check=True)

    # Stage a test file
    (path / "test.py").write_text("print('hello')\n")
    subprocess.run(["git", "add", "test.py"], cwd=str(path), capture_output=True, check=True)

    # Compute expected staged hash
    result = subprocess.run(
        ["git", "diff", "--cached", "--no-color", "--no-ext-diff"],
        cwd=str(path),
        capture_output=True,
        text=True,
    )
    return hashlib.sha256(result.stdout.encode()).hexdigest()


def _run_hook(tmp_path, installed_hook, env_override=None):
    """Run the installed pre-commit hook and return (stdout, stderr, rc)."""
    env = os.environ.copy()
    env.pop("APPSEC_HOOK_STRICT", None)
    if env_override:
        env.update(env_override)

    result = subprocess.run(
        ["bash", str(installed_hook)],
        capture_output=True,
        text=True,
        timeout=15,
        env=env,
        cwd=str(tmp_path),
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


@pytest.fixture
def hook_env(tmp_path):
    """Set up a complete hook testing environment with git repo."""
    installed_hook = _setup_plugin_structure(tmp_path)
    staged_hash = _init_git_repo(tmp_path)
    return tmp_path, installed_hook, staged_hash


class TestFailOpen:
    """Hook fails OPEN by default — plugin problems never block commits."""

    def test_no_scan_pass_warns_but_allows(self, hook_env):
        tmp_path, hook, _hash = hook_env
        # .scan-pass does not exist
        stdout, stderr, rc = _run_hook(tmp_path, hook)
        assert rc == 0, f"Expected fail-open (exit 0), got {rc}. stderr: {stderr}"
        assert "No scan pass found" in stderr
        assert "commit allowed" in stderr

    def test_stale_scan_pass_warns_but_allows(self, hook_env):
        tmp_path, hook, _hash = hook_env
        # Write a stale hash that doesn't match current staged diff
        (tmp_path / ".scan-pass").write_text("0" * 64)
        stdout, stderr, rc = _run_hook(tmp_path, hook)
        assert rc == 0, f"Expected fail-open (exit 0), got {rc}. stderr: {stderr}"
        assert "stale" in stderr
        assert "commit allowed" in stderr

    def test_missing_python_fails_open(self, hook_env):
        tmp_path, hook, _hash = hook_env
        # Write .scan-pass so hook proceeds to hash computation
        (tmp_path / ".scan-pass").write_text("something")
        # Break the python symlink
        python_link = tmp_path / ".venv" / "bin" / "python"
        python_link.unlink()
        python_link.symlink_to("/nonexistent/python3")

        stdout, stderr, rc = _run_hook(tmp_path, hook)
        assert rc == 0, f"Expected fail-open (exit 0), got {rc}. stderr: {stderr}"
        assert "commit allowed" in stderr


class TestFailClosed:
    """APPSEC_HOOK_STRICT=1 makes failures block the commit."""

    def test_no_scan_pass_blocks_in_strict_mode(self, hook_env):
        tmp_path, hook, _hash = hook_env
        stdout, stderr, rc = _run_hook(tmp_path, hook, {"APPSEC_HOOK_STRICT": "1"})
        assert rc == 1, f"Expected strict block (exit 1), got {rc}. stderr: {stderr}"
        assert "STRICT MODE" in stderr

    def test_stale_scan_pass_blocks_in_strict_mode(self, hook_env):
        tmp_path, hook, _hash = hook_env
        (tmp_path / ".scan-pass").write_text("0" * 64)
        stdout, stderr, rc = _run_hook(tmp_path, hook, {"APPSEC_HOOK_STRICT": "1"})
        assert rc == 1, f"Expected strict block (exit 1), got {rc}. stderr: {stderr}"
        assert "STRICT MODE" in stderr

    def test_missing_python_blocks_in_strict_mode(self, hook_env):
        tmp_path, hook, _hash = hook_env
        (tmp_path / ".scan-pass").write_text("something")
        python_link = tmp_path / ".venv" / "bin" / "python"
        python_link.unlink()
        python_link.symlink_to("/nonexistent/python3")

        stdout, stderr, rc = _run_hook(tmp_path, hook, {"APPSEC_HOOK_STRICT": "1"})
        assert rc == 1, f"Expected strict block (exit 1), got {rc}. stderr: {stderr}"
        assert "STRICT MODE" in stderr


class TestValidScanPass:
    """Valid .scan-pass matching current staged hash allows commit."""

    def test_matching_hash_allows_commit(self, hook_env):
        tmp_path, hook, staged_hash = hook_env
        (tmp_path / ".scan-pass").write_text(staged_hash)
        stdout, stderr, rc = _run_hook(tmp_path, hook)
        assert rc == 0, f"Expected exit 0 (allow), got {rc}. stderr: {stderr}"
        assert "STRICT" not in stderr
        assert "stale" not in stderr

    def test_hash_invalidated_by_new_staged_changes(self, hook_env):
        tmp_path, hook, staged_hash = hook_env
        (tmp_path / ".scan-pass").write_text(staged_hash)

        # Stage additional changes — invalidates the hash
        (tmp_path / "new_file.py").write_text("import os\n")
        subprocess.run(["git", "add", "new_file.py"], cwd=str(tmp_path), capture_output=True)

        stdout, stderr, rc = _run_hook(tmp_path, hook)
        # Fails open by default
        assert rc == 0
        assert "stale" in stderr

    def test_hash_invalidated_blocks_in_strict_mode(self, hook_env):
        tmp_path, hook, staged_hash = hook_env
        (tmp_path / ".scan-pass").write_text(staged_hash)

        # Stage additional changes
        (tmp_path / "extra.py").write_text("x = 1\n")
        subprocess.run(["git", "add", "extra.py"], cwd=str(tmp_path), capture_output=True)

        stdout, stderr, rc = _run_hook(tmp_path, hook, {"APPSEC_HOOK_STRICT": "1"})
        assert rc == 1
        assert "stale" in stderr


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_scan_pass_fails_open(self, hook_env):
        tmp_path, hook, _hash = hook_env
        (tmp_path / ".scan-pass").write_text("")
        stdout, stderr, rc = _run_hook(tmp_path, hook)
        assert rc == 0
        assert "stale" in stderr or "commit allowed" in stderr

    def test_scan_pass_with_trailing_newline(self, hook_env):
        """Trailing newlines in .scan-pass should be trimmed before comparison."""
        tmp_path, hook, staged_hash = hook_env
        (tmp_path / ".scan-pass").write_text(staged_hash + "\n")
        stdout, stderr, rc = _run_hook(tmp_path, hook)
        assert rc == 0
        assert "stale" not in stderr

    def test_hook_is_executable(self):
        """The hook script in the repo should be executable."""
        assert os.path.isfile(_GIT_HOOK_SCRIPT), f"Hook script not found: {_GIT_HOOK_SCRIPT}"
        assert os.access(_GIT_HOOK_SCRIPT, os.X_OK), (
            f"Hook script not executable: {_GIT_HOOK_SCRIPT}"
        )
