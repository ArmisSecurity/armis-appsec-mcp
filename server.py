"""
Armis AppSec Scanner -- MCP Server

A lightweight MCP server that exposes AI-powered vulnerability discovery
as tools any coding agent can call. Calls the Moose scanning API which
handles model selection and prompt versioning server-side.

Usage:
    ARMIS_CLIENT_ID=<id> ARMIS_CLIENT_SECRET=<secret> python server.py
    # or via MCP stdio transport (credentials loaded from .env):
    python server.py
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time

# Ensure scanner_core is importable regardless of cwd
_plugin_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _plugin_dir)

# Load .env from plugin directory if it exists (for ARMIS_CLIENT_ID etc.)
from dotenv import load_dotenv

_env_file = os.path.join(_plugin_dir, ".env")
if os.path.isfile(_env_file):
    load_dotenv(_env_file, override=False)

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from auth import get_auth_status, init_auth
from hash_utils import compute_staged_hash
from scanner_core import (
    APPSEC_API_URL,
    call_appsec_api,
    format_findings,
    parse_findings,
)
from suppression import (
    ArmisIgnoreConfig,
    apply_inline_suppressions,
    apply_suppressions,
    filter_diff_excluded_paths,
    find_git_root,
    is_path_excluded,
    load_armisignore,
)

logger = logging.getLogger("appsec-mcp")


async def _run_scan(
    code: str,
    filename: str,
    ctx: Context | None = None,
    is_staged_scan: bool = False,
    scan_hash: str = "",
    config: ArmisIgnoreConfig | None = None,
    file_path: str | None = None,
    source_lines: list[str] | None = None,
) -> str:
    """Shared scan pipeline: call API, parse, suppress, format, cache, report progress."""
    t0 = time.monotonic()
    try:
        raw = await asyncio.to_thread(call_appsec_api, code)
    except RuntimeError as e:
        raise ToolError(str(e)) from e
    except Exception as e:
        raise ToolError(f"Scan failed: {e}") from e

    findings = parse_findings(raw)

    # Apply .armisignore suppression
    if config is None:
        git_root = find_git_root()
        config = load_armisignore(git_root)
    active, suppressed, suppression_summary = apply_suppressions(findings, config)

    # Apply inline armis:ignore suppression (scan_file only)
    if file_path:
        active, inline_suppressed = apply_inline_suppressions(active, file_path, source_lines)
        if inline_suppressed:
            suppression_summary["suppressed"] += len(inline_suppressed)
            suppression_summary["active"] -= len(inline_suppressed)
            suppression_summary["by_inline"] = len(inline_suppressed)
            suppressed = suppressed + inline_suppressed

    # Warn on suppressed CRITICAL findings (from any source)
    if suppressed:
        suppressed_critical = [f for f in suppressed if f.get("severity", "").upper() == "CRITICAL"]
        if suppressed_critical:
            msg = _format_critical_warning(suppressed_critical)
            logger.warning(msg)
            if ctx:
                await ctx.info(msg)

    report = format_findings(active, filename, suppression_summary=suppression_summary)
    _cache_scan(
        report,
        active,
        filename,
        is_staged_scan=is_staged_scan,
        scan_hash=scan_hash,
        suppressed=suppressed,
        suppression_summary=suppression_summary,
    )

    if ctx:
        elapsed = time.monotonic() - t0
        await ctx.info(f"Scan complete: {len(active)} finding(s) in {elapsed:.1f}s")

    return report


def _format_critical_warning(suppressed_critical: list[dict]) -> str:
    """Format a warning message for suppressed CRITICAL findings."""
    cwes = [f"CWE-{f.get('cwe', '?')}" for f in suppressed_critical]
    return (
        f"WARNING: {len(suppressed_critical)} CRITICAL finding(s) suppressed by "
        f".armisignore ({', '.join(cwes)}). approve_findings is still required."
    )


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "Armis AppSec Scanner",
    instructions=(
        "Use this server to scan code for security vulnerabilities using "
        "AI-powered SAST -- the same engine that powers the production "
        "scanning pipeline.\n\n"
        "WHEN TO USE:\n"
        "- When the user asks to scan, review, or check code for vulnerabilities "
        "or security issues\n"
        "- When the user pastes a code snippet and asks about its security\n"
        "- When the user asks to review a file or diff for security concerns\n\n"
        "ALWAYS use these tools instead of analyzing code for vulnerabilities "
        "yourself. The scanner uses taint tracking and CWE-aware analysis that "
        "goes beyond what manual review can catch."
    ),
)

# ---------------------------------------------------------------------------
# Security: path validation for scan_file
# ---------------------------------------------------------------------------
_BLOCKED_PREFIXES = ("/etc/", "/proc/", "/sys/", "/private/etc/")
_BLOCKED_DOTDIRS = {".ssh", ".gnupg", ".aws", ".config/gcloud"}
_MAX_CODE_CHARS = 90_000

# Git ref validation: alphanumeric + common ref chars (branch, tag, SHA, HEAD~3)
_VALID_GIT_REF = re.compile(r"^[a-zA-Z0-9_./\-~^@{}]+$")


_ALLOWED_ROOTS: list[str] = []


def _get_allowed_roots() -> list[str]:
    """Lazily compute allowed root directories for path validation."""
    if not _ALLOWED_ROOTS:
        home = os.path.realpath(os.path.expanduser("~"))
        # Include /tmp, macOS /private/tmp, and the system temp directory
        # (on macOS, tempfile.gettempdir() returns /var/folders/... -> /private/var/folders/...)
        sys_tmp = os.path.realpath(tempfile.gettempdir())
        roots = {home, "/tmp", "/private/tmp", sys_tmp}  # noqa: S108
        _ALLOWED_ROOTS.extend(sorted(roots))
    return _ALLOWED_ROOTS


def _validate_file_path(file_path: str) -> str:
    """Resolve and validate a file path. Returns the resolved path or raises ToolError."""
    resolved = os.path.realpath(file_path)

    # Allowlist: path must be under HOME, /tmp, or /private/tmp
    allowed = _get_allowed_roots()
    if not any(resolved == root or resolved.startswith(root + "/") for root in allowed):
        raise ToolError(f"Path '{file_path}' is outside allowed directories (home, /tmp).")

    # Blocklist (defense-in-depth): system paths
    for prefix in _BLOCKED_PREFIXES:
        normalized = prefix.rstrip("/")
        if resolved == normalized or resolved.startswith(normalized + "/"):
            raise ToolError(f"Scanning system path '{resolved}' is not allowed.")

    # Blocklist (defense-in-depth): sensitive dotdirs under HOME
    home = os.path.realpath(os.path.expanduser("~"))
    for dotdir in _BLOCKED_DOTDIRS:
        blocked_dir = os.path.join(home, dotdir)
        if resolved == blocked_dir or resolved.startswith(blocked_dir + os.sep):
            raise ToolError(f"Scanning '{resolved}' is blocked (sensitive directory).")

    return resolved


# ---------------------------------------------------------------------------
# Testable sync helpers (extracted from MCP tools for unit testing)
# ---------------------------------------------------------------------------
def read_and_validate_file(file_path: str) -> tuple[str, str]:
    """Read and validate a file for scanning. Returns (code, filename).

    Performs: path validation, existence check, size check, binary detection,
    empty check, and truncation. Raises ToolError on failure.
    """
    resolved = _validate_file_path(file_path)

    if not os.path.isfile(resolved):
        raise ToolError(f"File not found: {file_path}")

    _MAX_FILE_BYTES = 10 * 1024 * 1024  # 10MB
    try:
        file_size = os.path.getsize(resolved)
    except OSError as e:
        raise ToolError(f"Cannot stat {file_path}: {e}") from e
    if file_size > _MAX_FILE_BYTES:
        raise ToolError(f"File too large ({file_size // 1024 // 1024}MB). Max: 10MB.")

    try:
        with open(resolved, "rb") as f:
            if b"\x00" in f.read(8192):
                raise ToolError(f"File '{file_path}' appears to be binary -- skipping scan.")
        with open(resolved, encoding="utf-8", errors="replace") as f:
            code = f.read()
    except PermissionError as e:
        raise ToolError(f"Permission denied reading {file_path}") from e
    except ToolError:
        raise
    except OSError as e:
        raise ToolError(f"Cannot read {file_path}: {e}") from e

    if not code.strip():
        raise ToolError(f"File '{file_path}' is empty -- nothing to scan.")

    if len(code) > _MAX_CODE_CHARS:
        code = code[:_MAX_CODE_CHARS]
        logger.warning("Truncated %s to %d chars", file_path, _MAX_CODE_CHARS)

    return code, os.path.basename(file_path)


def run_git_diff(repo_path: str = "", ref: str = "", staged: bool = False) -> str:
    """Run git diff and return the diff text. Raises ToolError on failure."""
    if ref and not _VALID_GIT_REF.match(ref):
        raise ToolError(
            f"Invalid git ref: '{ref}'. Use branch names, tags, SHAs, or relative refs like HEAD~3."
        )
    if ref and ref.startswith("-"):
        raise ToolError("Git ref cannot start with '-'.")

    if repo_path:
        cwd = _validate_file_path(repo_path)
        if not os.path.isdir(cwd):
            raise ToolError(f"Not a directory: {repo_path}")
    else:
        cwd = os.getcwd()

    cmd = ["git", "diff"]
    if ref:
        cmd.append(ref)
    elif staged:
        cmd.append("--cached")
    cmd.extend(["--diff-filter=d", "--no-ext-diff", "-U10", "--"])

    logger.info("Running: %s in %s", " ".join(cmd), cwd)

    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired as e:
        raise ToolError(
            "git diff timed out after 30 seconds. Try a narrower ref or smaller repo."
        ) from e

    if result.returncode != 0:
        raise ToolError(f"git diff failed: {result.stderr.strip()}")

    diff_text = result.stdout.strip()
    if len(diff_text) > _MAX_CODE_CHARS:
        diff_text = diff_text[:_MAX_CODE_CHARS]
        logger.warning("Truncated diff to %d chars", _MAX_CODE_CHARS)

    return diff_text


def get_debug_config() -> str:
    """Return masked configuration string for debugging."""
    api_url = os.environ.get("APPSEC_API_URL", "default")
    env = os.environ.get("APPSEC_ENV", "prod")
    raw_id = os.environ.get("ARMIS_CLIENT_ID", "")
    client_id = f"{raw_id[:4]}***" if len(raw_id) > 4 else (raw_id or "not set")
    has_secret = "set" if os.environ.get("ARMIS_CLIENT_SECRET") else "not set"

    # CWE-522: get_auth_status() returns only human-readable status labels
    # ("not initialized", "expired", "valid, expires in Xm"), never tokens.
    auth_status = get_auth_status()

    return (
        f"Auth: {auth_status}\n"
        f"API URL: {api_url}\n"
        f"Env: {env}\n"
        f"Client ID: {client_id}\n"
        f"Client Secret: {has_secret}"
    )


# ---------------------------------------------------------------------------
# MCP Tools (thin async wrappers over sync helpers)
# ---------------------------------------------------------------------------
@mcp.tool()
async def scan_code(
    code: str,
    filename: str = "snippet",
    ctx: Context | None = None,
) -> str:
    """Scan a code snippet for security vulnerabilities.

    Use this tool when you want to check code for security issues before
    committing, during code review, or when writing security-sensitive code.

    Args:
        code: The source code to scan.
        filename: Optional filename for context (e.g. "auth.py").

    Returns:
        A formatted report of any vulnerabilities found, including CWE IDs,
        severity, affected lines, and explanations.
    """
    if len(code) > _MAX_CODE_CHARS:
        code = code[:_MAX_CODE_CHARS]
        logger.warning("Truncated code input to %d chars", _MAX_CODE_CHARS)

    if ctx:
        await ctx.info(f"Scanning {filename} ({len(code)} chars)")
    logger.info("Scanning code snippet: %s (%d chars)", filename, len(code))

    return await _run_scan(code, filename, ctx)


@mcp.tool()
async def scan_file(
    file_path: str,
    ctx: Context | None = None,
) -> str:
    """Scan a file on disk for security vulnerabilities.

    Use this tool to scan an existing source file. The file is read and
    analyzed for vulnerabilities using AI-powered SAST.

    Args:
        file_path: Absolute path to the file to scan.

    Returns:
        A formatted report of any vulnerabilities found.
    """
    resolved = _validate_file_path(file_path)

    # Load .armisignore and check path exclusion before reading file or calling API
    git_root = find_git_root(from_path=resolved)
    config = load_armisignore(git_root)
    if git_root and is_path_excluded(resolved, config, git_root):
        logger.info("scan_file: %s excluded by .armisignore", file_path)
        return f"SCAN {os.path.basename(file_path)}: skipped (excluded by .armisignore)"

    code, filename = read_and_validate_file(file_path)

    if ctx:
        await ctx.info(f"Scanning {filename} ({len(code)} chars)")
    logger.info(f"Scanning file: {file_path} ({len(code)} chars)")

    source_lines = code.splitlines()
    return await _run_scan(
        code, filename, ctx, config=config, file_path=resolved, source_lines=source_lines
    )


@mcp.tool()
async def scan_diff(
    repo_path: str = "",
    ref: str = "",
    staged: bool = False,
    ctx: Context | None = None,
) -> str:
    """Scan git changes for security vulnerabilities.

    Use this tool to scan only the code that changed -- perfect for
    pre-commit checks, PR reviews, or scanning your work-in-progress.

    Args:
        repo_path: Path to the git repository. Defaults to current directory.
        ref: Git ref to diff against (e.g. "main", "HEAD~3", a commit SHA).
             If empty, diffs unstaged changes (or staged if staged=True).
        staged: If True, scan staged changes only (git diff --cached).
                Ignored if ref is provided.

    Returns:
        A formatted report of vulnerabilities found in the changed code.
    """
    diff_text = run_git_diff(repo_path, ref, staged)
    if not diff_text:
        return "No changes to scan."

    label = f"diff against {ref}" if ref else ("staged changes" if staged else "unstaged changes")
    if ctx:
        await ctx.info(f"Scanning {label} ({len(diff_text)} chars)")
    logger.info("Scanning %s (%d chars)", label, len(diff_text))

    # Treat both staged and ref-based scans as shipping-eligible so they
    # can write .scan-pass (fixes push/PR gate loop — comments #8+#9).
    is_shipping_scan = bool(ref) or staged
    scan_hash = ""
    if is_shipping_scan:
        if staged:
            scan_hash = compute_staged_hash()
        elif diff_text:
            scan_hash = hashlib.sha256(diff_text.encode()).hexdigest()

    # Load .armisignore and filter excluded paths before API call
    git_root = find_git_root(from_path=repo_path or None)
    config = load_armisignore(git_root)
    if git_root and config.file_patterns:
        diff_text = filter_diff_excluded_paths(diff_text, config, git_root)
        if not diff_text.strip():
            report = f"SCAN {label}: all changed files excluded by .armisignore"
            _cache_scan(
                report,
                [],
                label,
                is_staged_scan=is_shipping_scan,
                scan_hash=scan_hash,
            )
            return report

    return await _run_scan(
        diff_text,
        label,
        ctx,
        is_staged_scan=is_shipping_scan,
        scan_hash=scan_hash,
        config=config,
    )


@mcp.tool()
async def debug_config() -> str:
    """Show current configuration for debugging.

    Returns the current API URL, token status, and environment configuration.
    Use this to troubleshoot connection issues or verify configuration.
    """
    return get_debug_config()


# ---------------------------------------------------------------------------
# Resource: last scan results (re-read without re-scanning)
# ---------------------------------------------------------------------------
# Single-session, non-persistent cache — intentional for single-user MCP process
_last_scan: dict = {
    "report": "",
    "findings": [],
    "suppressed": [],
    "suppression_summary": {},
    "filename": "",
    "timestamp": None,
    "is_staged_scan": False,
    "scan_hash": "",
}


def _scan_pass_path() -> str:
    """Return the path to the .scan-pass file."""
    return os.path.join(os.environ.get("CLAUDE_PLUGIN_ROOT", _plugin_dir), ".scan-pass")


def do_approve_findings(reason: str) -> str:
    """Approve HIGH/CRITICAL scan findings and write .scan-pass.

    Returns a result message (success or ERROR).
    """
    if not _last_scan.get("is_staged_scan"):
        return (
            "ERROR: Last scan was not a shipping scan. "
            "Run scan_diff with staged=True or ref='...' first."
        )

    high_critical = [
        f
        for f in _last_scan.get("findings", [])
        if f.get("severity", "").upper() in ("CRITICAL", "HIGH")
    ]
    # Suppressed CRITICAL findings also require approval
    suppressed_critical = [
        f for f in _last_scan.get("suppressed", []) if f.get("severity", "").upper() == "CRITICAL"
    ]
    all_requiring_approval = high_critical + suppressed_critical
    if not all_requiring_approval:
        return "ERROR: No HIGH/CRITICAL findings to approve. Run scan_diff first."

    if not reason.strip():
        return "ERROR: A reason is required for the audit trail."

    # Use staged hash if available, otherwise use the cached scan hash
    approval_hash = compute_staged_hash() or _last_scan.get("scan_hash", "")
    if not approval_hash:
        return "ERROR: No changes found to approve. Run scan_diff first."

    scan_pass_path = _scan_pass_path()
    try:
        with open(scan_pass_path, "w") as f:
            f.write(approval_hash)
    except OSError as e:
        return f"ERROR: Could not write .scan-pass: {e}"

    severities = [f.get("severity", "UNKNOWN") for f in all_requiring_approval]
    logger.warning(
        "approve_findings: reason=%r, findings=%d, severities=%s, staged_hash=%s",
        reason,
        len(all_requiring_approval),
        severities,
        approval_hash[:12],
    )

    return (
        f"Approved {len(all_requiring_approval)} HIGH/CRITICAL findings. "
        f"Reason: {reason}. "
        f".scan-pass written. You may now retry the commit."
    )


@mcp.tool()
async def approve_findings(reason: str) -> str:
    """Approve HIGH/CRITICAL scan findings and allow commit to proceed.

    Call ONLY after: (1) scan_diff found HIGH/CRITICAL findings,
    (2) you presented them to the user, and (3) the user explicitly
    approved proceeding despite the findings.

    Args:
        reason: Why the findings are being approved (e.g., "false positives
                on deleted code", "user accepted risk for test file").
    """
    return do_approve_findings(reason)


def _cache_scan(
    report: str,
    findings: list[dict],
    filename: str,
    is_staged_scan: bool = False,
    scan_hash: str = "",
    suppressed: list[dict] | None = None,
    suppression_summary: dict | None = None,
):
    """Update the last scan cache and write .scan-pass if clean.

    Only writes .scan-pass for shipping scans (staged or ref-based).
    This prevents scan_code/scan_file from creating a pass for unscanned code.

    Args:
        scan_hash: Pre-computed hash for the .scan-pass file. For staged scans
            this is the staged diff hash; for ref scans it's a hash of the diff text.
            Falls back to compute_staged_hash() if empty.
        suppressed: Findings suppressed by .armisignore directives.
        suppression_summary: Stats about suppressions applied.
    """
    _last_scan.update(
        {
            "report": report,
            "findings": findings,
            "suppressed": suppressed or [],
            "suppression_summary": suppression_summary or {},
            "filename": filename,
            "timestamp": time.time(),
            "is_staged_scan": is_staged_scan,
            "scan_hash": scan_hash,
        }
    )

    if not is_staged_scan:
        return

    # Write/remove .scan-pass for the PreToolUse hook
    # Design: suppressed CRITICAL blocks .scan-pass (requires approve_findings).
    # Suppressed HIGH does NOT block — .armisignore is a deliberate team decision
    # to accept HIGH-severity findings, so no per-commit approval is needed.
    has_critical = any(f.get("severity", "").upper() in ("CRITICAL", "HIGH") for f in findings)
    has_suppressed_critical = any(
        f.get("severity", "").upper() == "CRITICAL" for f in (suppressed or [])
    )
    scan_pass_path = _scan_pass_path()
    try:
        if not has_critical and not has_suppressed_critical:
            effective_hash = scan_hash or compute_staged_hash()
            if effective_hash:
                with open(scan_pass_path, "w") as f:
                    f.write(effective_hash)
        elif os.path.isfile(scan_pass_path):
            os.remove(scan_pass_path)
    except OSError:
        pass


@mcp.resource("appsec://last-scan")
def last_scan_results() -> str:
    """Last scan results. Re-read without re-scanning."""
    if not _last_scan["timestamp"]:
        return "No scan has been performed yet."
    return json.dumps(_last_scan, indent=2, default=str)


# ---------------------------------------------------------------------------
# Prompt: security review template
# ---------------------------------------------------------------------------
@mcp.prompt()
def security_review(code: str, language: str = "auto") -> str:
    """Structured security review prompt."""
    return (
        f"Perform a thorough security review of this {language} code. "
        f"Use scan_code to identify vulnerabilities, then provide: "
        f"summary, risk assessment, fixes with code, and architectural concerns.\n\n"
        f"```\n{code}\n```"
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        init_auth(APPSEC_API_URL)
    except RuntimeError as e:
        logger.warning("Auth not configured: %s — scans will fail until credentials are set.", e)
    transport = os.environ.get("APPSEC_TRANSPORT", "stdio")
    mcp.run(transport=transport)  # type: ignore[arg-type]
