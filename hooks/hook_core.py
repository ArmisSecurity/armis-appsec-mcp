#!/usr/bin/env python3
"""Shared gate logic for all client hook adapters.

Extracted from pre_commit_scan.py so that Gemini, Codex, and Cursor adapters
can reuse the same detection and validation without duplicating code.
Each adapter handles its own stdin/stdout JSON format; this module provides
the client-agnostic decision logic.
"""

import os
import re
import sys
from typing import NamedTuple

_plugin_root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _plugin_root_dir not in sys.path:
    sys.path.insert(0, _plugin_root_dir)

from hash_utils import compute_staged_hash  # noqa: E402

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class GateResult(NamedTuple):
    decision: str  # "allow" | "deny"
    system_message: str  # scan instruction (empty string if allow)


# ---------------------------------------------------------------------------
# Shipping command patterns
# ---------------------------------------------------------------------------
GIT_SHIPPING_PATTERNS = [
    re.compile(r"(?:^|&&|\|\||;)\s*git\s+commit\b"),
    re.compile(r"(?:^|&&|\|\||;)\s*git\s+push\b"),
    re.compile(r"(?:^|&&|\|\||;)\s*gh\s+pr\s+create\b"),
]

_PUSH_PR_PATTERNS = [
    re.compile(r"(?:^|&&|\|\||;)\s*git\s+push\b"),
    re.compile(r"(?:^|&&|\|\||;)\s*gh\s+pr\s+create\b"),
]

_COMMIT_ALL_FLAG = re.compile(r"\bgit\s+commit\b.*(?:\s-a\b|\s--all\b)")

_SCAN_PASS_WRITE_PATTERN = re.compile(
    r"[>|][^;&|]*(?:^|/)\.scan-pass\b" r"|(?:tee|cp|mv)\s+[^;&|]*(?:^|/)\.scan-pass\b"
)


# ---------------------------------------------------------------------------
# Detection helpers (public for backward compat with existing tests)
# ---------------------------------------------------------------------------


def _is_shipping_command(cmd: str) -> bool:
    """Check if the command matches any git shipping pattern."""
    return any(p.search(cmd) for p in GIT_SHIPPING_PATTERNS)


def _is_push_or_pr(cmd: str) -> bool:
    """Check if the command is a git push or gh pr create."""
    return any(p.search(cmd) for p in _PUSH_PR_PATTERNS)


def _has_all_flag(cmd: str) -> bool:
    """Check if git commit has -a or --all flag."""
    return bool(_COMMIT_ALL_FLAG.search(cmd))


def _is_scan_pass_write_bash(cmd: str) -> bool:
    """Check if a Bash command attempts to write to .scan-pass."""
    return bool(_SCAN_PASS_WRITE_PATTERN.search(cmd))


def is_scan_pass_file(file_path: str) -> bool:
    """Check if a file path targets .scan-pass (for Write/Edit guard)."""
    if not isinstance(file_path, str) or not file_path.strip():
        return False
    return os.path.basename(file_path) == ".scan-pass"


# ---------------------------------------------------------------------------
# Plugin root resolution
# ---------------------------------------------------------------------------


def _find_git_root(start_path: str):
    """Walk up from start_path to find .git directory."""
    current = os.path.abspath(start_path)
    for _ in range(50):
        if os.path.isdir(os.path.join(current, ".git")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


def resolve_plugin_root() -> str:
    """Resolve the plugin root directory.

    Checks CLAUDE_PLUGIN_ROOT (set by Claude Code runtime), validates it
    against CWE-73 (must be within a git repo), falls back to this script's
    grandparent directory.
    """
    fallback = _plugin_root_dir
    raw = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    if raw:
        resolved = os.path.realpath(raw)
        if os.path.isdir(resolved):
            try:
                git_root = _find_git_root(resolved)
                if git_root:
                    resolved_abs = os.path.abspath(resolved)
                    git_root_abs = os.path.abspath(git_root)
                    if (
                        resolved_abs.startswith(git_root_abs + os.sep)
                        or resolved_abs == git_root_abs
                    ):
                        return resolved
            except (OSError, ValueError):
                pass
    return fallback


# ---------------------------------------------------------------------------
# Scan pass validation
# ---------------------------------------------------------------------------


def _has_matching_scan_pass() -> bool:
    """Check if .scan-pass hash matches current staged changes."""
    scan_pass_path = os.path.join(resolve_plugin_root(), ".scan-pass")
    try:
        if not os.path.isfile(scan_pass_path):
            return False
        with open(scan_pass_path) as f:
            stored_hash = f.read().strip()
        if not stored_hash:
            return False
        current_hash = compute_staged_hash()
        if not current_hash:
            return False
        return stored_hash == current_hash
    except OSError:
        return False


def _has_scan_pass_for_push() -> bool:
    """For push/PR: check that a .scan-pass file exists."""
    scan_pass_path = os.path.join(resolve_plugin_root(), ".scan-pass")
    try:
        return os.path.isfile(scan_pass_path)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# System message builder
# ---------------------------------------------------------------------------


def build_system_message(cmd: str) -> str:
    """Build the scan instruction based on command type."""
    if _is_push_or_pr(cmd):
        scan_instruction = "scan_diff(ref='origin/HEAD')"
    elif _has_all_flag(cmd):
        scan_instruction = "scan_diff()"
    else:
        scan_instruction = "scan_diff(staged=True)"

    return (
        f"Security scan required before shipping. "
        f"Call {scan_instruction} to scan your changes. "
        f"After scanning:\n"
        f"- If clean (no HIGH/CRITICAL findings): retry the original command.\n"
        f"- If HIGH/CRITICAL findings: fix what you can (move secrets to env vars, "
        f"mask tokens, set debug=False), re-stage, and re-scan.\n"
        f"- If HIGH/CRITICAL findings remain after remediation: present them to the "
        f"user and ask whether to proceed. Do NOT call approve_findings on your own "
        f"- wait for the user to explicitly say to proceed. If the user approves, "
        f"call approve_findings(reason='<quote the user stated reason>') then retry "
        f"the original command.\n"
        f"MEDIUM/LOW/INFO findings can be ignored."
    )


# ---------------------------------------------------------------------------
# Main gate logic
# ---------------------------------------------------------------------------

_SCAN_PASS_WRITE_DENY_MSG = "BLOCKED: Direct writes to .scan-pass are not allowed. The scan-pass file is managed by the security scanner. Run scan_diff() to scan your code instead."  # noqa: S105, E501


def check_gate(cmd: str) -> GateResult:
    """Main entry point: evaluate a shell command against the security gate.

    Returns GateResult with decision="allow" or decision="deny" plus system_message.
    """
    if _is_scan_pass_write_bash(cmd):
        return GateResult("deny", _SCAN_PASS_WRITE_DENY_MSG)

    if not _is_shipping_command(cmd):
        return GateResult("allow", "")

    if _is_push_or_pr(cmd):
        if _has_scan_pass_for_push():
            return GateResult("allow", "")
    elif _has_matching_scan_pass():
        return GateResult("allow", "")

    return GateResult("deny", build_system_message(cmd))
