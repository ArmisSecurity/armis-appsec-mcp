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

from hash_utils import (  # noqa: E402
    compute_staged_hash,
    resolve_repo_toplevel,
    resolve_scan_pass_path,
)

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

# Matches both the current "armis-scan-pass" and the legacy ".scan-pass".
_SCAN_PASS_NAMES = r"(?:\.scan-pass|armis-scan-pass)"  # noqa: S105 — filenames, not a secret
_SCAN_PASS_WRITE_PATTERN = re.compile(
    rf"[>|][^;&|]*(?:^|/|\s){_SCAN_PASS_NAMES}\b"
    rf"|(?:tee|cp|mv)\s+[^;&|]*(?:^|/|\s){_SCAN_PASS_NAMES}\b"
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
    """Check if a file path targets the scan-pass file (for Write/Edit guard).

    Matches both the current "armis-scan-pass" and the legacy ".scan-pass".
    """
    if not isinstance(file_path, str) or not file_path.strip():
        return False
    return os.path.basename(file_path) in ("armis-scan-pass", ".scan-pass")


# ---------------------------------------------------------------------------
# Scan pass validation
# ---------------------------------------------------------------------------
#
# The gate (reader) MUST locate the scan-pass with the exact same logic as the
# scanner (writer). Both call hash_utils.resolve_scan_pass_path(), which uses
# `git rev-parse --absolute-git-dir`. A previous version resolved the path here
# with a private filesystem walker using os.path.isdir(".git"); inside a git
# worktree (every Conductor workspace) `.git` is a *file*, so that walker
# silently disagreed with the writer's os.path.exists check and the gate denied
# forever. Delegating to git removes that whole class of bug.


def _has_matching_scan_pass() -> bool:
    """Check if the scan-pass hash matches current staged changes."""
    scan_pass_path = resolve_scan_pass_path()
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
    """For push/PR: check that a scan-pass file exists."""
    scan_pass_path = resolve_scan_pass_path()
    try:
        return os.path.isfile(scan_pass_path)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# System message builder
# ---------------------------------------------------------------------------


def _scan_call(cmd: str, repo_path: str | None) -> str:
    """Build the ``scan_diff(...)`` call string for the given command.

    ``repo_path`` (the hook's own work-tree root) is injected so the MCP
    server scans — and writes the scan-pass into — the *same* repo the commit
    will happen in. The server is long-lived and pinned to its launch CWD,
    which in a Conductor setup is often the main checkout, not this worktree;
    without this argument the server would write the scan-pass into the wrong
    git dir and the gate (reading from here) would never see it.
    """
    if _is_push_or_pr(cmd):
        args = ["ref='origin/HEAD'"]
    elif _has_all_flag(cmd):
        args = []
    else:
        args = ["staged=True"]

    if repo_path:
        # Single-quote the path; the agent reproduces this call verbatim.
        args.append(f"repo_path='{repo_path}'")
    return f"scan_diff({', '.join(args)})"


def build_system_message(cmd: str, repo_path: str | None = None) -> str:
    """Build the scan instruction based on command type.

    ``repo_path`` defaults to the hook's resolved work-tree root; tests pass it
    explicitly. It is woven into the recommended ``scan_diff`` call so the
    scan-pass is written where this gate will read it.
    """
    if repo_path is None:
        repo_path = resolve_repo_toplevel()

    scan_instruction = _scan_call(cmd, repo_path)

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
