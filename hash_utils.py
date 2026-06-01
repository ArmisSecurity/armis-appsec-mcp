"""Shared hash utilities for the AppSec MCP plugin.

Used by both server.py and the hooks to compute the staged diff hash and to
locate the scan-pass commit-gate file.
"""

import hashlib
import os
import subprocess

_MAX_DIFF_BYTES = 50 * 1024 * 1024  # 50 MB — safety limit for hashing
_plugin_dir = os.path.dirname(os.path.abspath(__file__))

# The scan-pass lives inside .git/ under this name (no leading dot — it is
# already inside a hidden directory; the "armis-" prefix avoids colliding with
# git's own internal files).
SCAN_PASS_BASENAME = "armis-scan-pass"  # noqa: S105 — filename, not a secret
# Earlier versions wrote this into the working tree root.
LEGACY_SCAN_PASS_BASENAME = ".scan-pass"  # noqa: S105 — filename, not a secret


def _git_output(args: list[str]) -> str | None:
    """Run a read-only git command from CWD; return stripped stdout or None.

    Mirrors suppression.find_git_root: short timeout, fail-soft on any error
    (missing git binary, not a repo, timeout).
    """
    try:
        result = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0:
        return None
    out = result.stdout.strip()
    return out or None


def resolve_scan_pass_path() -> str:
    """Return the canonical absolute path to the scan-pass file.

    The file lives inside the repository's git directory
    (``git rev-parse --absolute-git-dir``) as ``armis-scan-pass``. This keeps
    it out of the working tree and ensures the MCP server, the Claude Code
    hooks, and the portable git hook all resolve the *same* path.

    ``--absolute-git-dir`` (rather than the work-tree root) is what makes this
    correct inside git worktrees — every Conductor workspace is a worktree,
    where ``.git`` is a *file*, not a directory, so filesystem ``.git``
    detection diverges. It also returns the *per-worktree* git dir, keeping
    each worktree's scan-pass isolated to match its per-worktree staged index.

    Falls back to the plugin install directory only when CWD is not a git
    repository (in which case there is no commit to gate anyway). Reader and
    writer share this function, so they agree even in the fallback case.
    """
    git_dir = _git_output(["rev-parse", "--absolute-git-dir"])
    if git_dir:
        return os.path.join(git_dir, SCAN_PASS_BASENAME)
    return os.path.join(_plugin_dir, SCAN_PASS_BASENAME)


def cleanup_legacy_scan_pass() -> None:
    """Best-effort removal of a legacy ``.scan-pass`` at the work-tree root.

    Earlier versions wrote ``.scan-pass`` into the working tree, where it
    showed up in ``git status`` and file explorers. Now that the file lives
    inside ``.git/``, delete any leftover so it stops polluting the project.
    Silently does nothing outside a git repo or on any IO error.
    """
    toplevel = _git_output(["rev-parse", "--show-toplevel"])
    if not toplevel:
        return
    legacy = os.path.join(toplevel, LEGACY_SCAN_PASS_BASENAME)
    try:
        if os.path.isfile(legacy):
            os.remove(legacy)
    except OSError:
        pass


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
