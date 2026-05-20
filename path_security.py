"""
Path validation for the Armis AppSec MCP plugin.

Provides allowlist/blocklist path validation used by both server.py (scan_file)
and context.py (import resolution). Extracted to avoid circular imports.
"""

import os
import tempfile

from mcp.server.fastmcp.exceptions import ToolError

BLOCKED_PREFIXES = ("/etc/", "/proc/", "/sys/", "/private/etc/")
BLOCKED_DOTDIRS = {".ssh", ".gnupg", ".aws", ".config/gcloud"}
MAX_CODE_CHARS = 90_000

_ALLOWED_ROOTS: list[str] = []


def get_allowed_roots() -> list[str]:
    """Lazily compute allowed root directories for path validation."""
    if not _ALLOWED_ROOTS:
        home = os.path.realpath(os.path.expanduser("~"))
        sys_tmp = os.path.realpath(tempfile.gettempdir())
        roots = {home, "/tmp", "/private/tmp", sys_tmp}  # noqa: S108
        _ALLOWED_ROOTS.extend(sorted(roots))
    return _ALLOWED_ROOTS


def validate_file_path(file_path: str) -> str:
    """Resolve and validate a file path. Returns the resolved path or raises ToolError."""
    resolved = os.path.realpath(file_path)

    allowed = get_allowed_roots()
    if not any(resolved == root or resolved.startswith(root + "/") for root in allowed):
        raise ToolError(f"Path '{file_path}' is outside allowed directories (home, /tmp).")

    for prefix in BLOCKED_PREFIXES:
        normalized = prefix.rstrip("/")
        if resolved == normalized or resolved.startswith(normalized + "/"):
            raise ToolError(f"Scanning system path '{resolved}' is not allowed.")

    home = os.path.realpath(os.path.expanduser("~"))
    for dotdir in BLOCKED_DOTDIRS:
        blocked_dir = os.path.join(home, dotdir)
        if resolved == blocked_dir or resolved.startswith(blocked_dir + os.sep):
            raise ToolError(f"Scanning '{resolved}' is blocked (sensitive directory).")

    return resolved
