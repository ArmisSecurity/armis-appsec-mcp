"""Shared hash utilities for the AppSec MCP plugin.

Used by both server.py and hooks/pre_commit_scan.py to compute
the staged diff hash for the .scan-pass commit gate.
"""

import hashlib
import os
import subprocess

_MAX_DIFF_BYTES = 50 * 1024 * 1024  # 50 MB — safety limit for hashing
_plugin_dir = os.path.dirname(os.path.abspath(__file__))


def _find_git_root(start_path: str) -> str | None:
    """Walk up from start_path to find a git repository root."""
    current = os.path.abspath(start_path)
    for _ in range(50):
        if os.path.exists(os.path.join(current, ".git")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


def resolve_scan_pass_path() -> str:
    """Return the canonical path to the .scan-pass file.

    Resolution order:
    1. CLAUDE_PLUGIN_ROOT env var (if set, dir exists, within a git repo)
    2. CWD's git root (for Cursor, VS Code, Gemini, Copilot CLI)
    3. Plugin install directory (final fallback)
    """
    raw = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    if raw:
        resolved = os.path.realpath(raw)
        if os.path.isdir(resolved):
            git_root = _find_git_root(resolved)
            if git_root:
                resolved_abs = os.path.abspath(resolved)
                git_root_abs = os.path.abspath(git_root)
                if resolved_abs.startswith(git_root_abs + os.sep) or resolved_abs == git_root_abs:
                    return os.path.join(resolved, ".scan-pass")

    cwd_git_root = _find_git_root(os.getcwd())
    if cwd_git_root:
        return os.path.join(cwd_git_root, ".scan-pass")

    return os.path.join(_plugin_dir, ".scan-pass")


def compute_staged_hash() -> str:
    """Compute SHA-256 hash of the current staged diff."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--no-color", "--no-ext-diff"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0 or not result.stdout:
            return ""
        if len(result.stdout) > _MAX_DIFF_BYTES:
            return ""  # Too large to hash safely
        return hashlib.sha256(result.stdout.encode()).hexdigest()
    except (subprocess.TimeoutExpired, OSError):
        return ""
