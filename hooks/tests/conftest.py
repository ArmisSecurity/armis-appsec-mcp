"""Shared fixtures for pre_commit_scan.py hook tests."""

import json
import os
import subprocess
import sys

import pytest

# Path to the hook script (system under test)
HOOK_PATH = os.path.join(os.path.dirname(__file__), "..", "pre_commit_scan.py")

# Add hooks dir to sys.path so unit tests can import pre_commit_scan directly
_hooks_dir = os.path.join(os.path.dirname(__file__), "..")
if _hooks_dir not in sys.path:
    sys.path.insert(0, _hooks_dir)

# Add tests dir to sys.path so test modules can import transcript_builder
_tests_dir = os.path.dirname(__file__)
if _tests_dir not in sys.path:
    sys.path.insert(0, _tests_dir)


@pytest.fixture
def hook_module():
    """Import pre_commit_scan module for direct function calls in unit tests.

    Never call main() directly — it calls sys.exit(). Use run_hook() for that.
    """
    import pre_commit_scan

    return pre_commit_scan


@pytest.fixture
def run_hook(tmp_path):
    """Run pre_commit_scan.py as a subprocess with PreToolUse input format.

    The hook subprocess runs with cwd=tmp_path so that _compute_staged_hash()
    can find the git repo created by test helpers like _init_git_repo().

    Initializes a bare git repo in tmp_path so that CLAUDE_PLUGIN_ROOT passes
    CWE-73 validation (must be within a git repo) and doesn't fall back to the
    real plugin root which may have a .scan-pass from development usage.

    Returns:
        Tuple of (stdout_str, stderr_str, returncode).
    """
    # Ensure tmp_path is a git repo so _plugin_root() CWE-73 validation passes
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)

    def _run(command="", tool_name="Bash", env_override=None):
        hook_input = {"tool_name": tool_name, "tool_input": {"command": command}}

        env = os.environ.copy()
        # Use tmp_path for .scan-pass so tests don't interfere
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
        return result.stdout.strip(), result.stderr.strip(), result.returncode

    return _run


@pytest.fixture
def run_hook_raw(tmp_path):
    """Run pre_commit_scan.py as a subprocess with raw string stdin.

    Use this for error-handling tests where the input is not valid JSON.
    Returns the CompletedProcess for full inspection.
    """
    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True, check=True)

    def _run(raw_stdin=""):
        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path)

        result = subprocess.run(
            [sys.executable, HOOK_PATH],
            input=raw_stdin,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
            cwd=str(tmp_path),
        )
        return result

    return _run
