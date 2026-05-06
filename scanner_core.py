"""
Armis AppSec Scanner Core

Shared scanning logic used by the MCP server, hooks, and any other surface.

Calls the Moose scanning API (POST /api/v1/scan/fast) which proxies the LLM
call server-side.  Authenticates via JWT (ARMIS_CLIENT_ID / ARMIS_CLIENT_SECRET).
"""

import json
import logging
import os
import re
import urllib.parse

import httpx

from auth import get_auth_header

logger = logging.getLogger("appsec-mcp")

# ---------------------------------------------------------------------------
# Output formatting constants
# ---------------------------------------------------------------------------
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1"}

# ---------------------------------------------------------------------------
# API configuration
# ---------------------------------------------------------------------------
_API_URLS = {
    "dev": "https://moose-dev.armis.com/api/v1",
    "prod": "https://moose.armis.com/api/v1",
}
_APPSEC_ENV = os.environ.get("APPSEC_ENV", "prod")
APPSEC_API_URL = os.environ.get("APPSEC_API_URL", _API_URLS.get(_APPSEC_ENV, _API_URLS["prod"]))

SCAN_MODE = "fast"


# ---------------------------------------------------------------------------
# API call
# ---------------------------------------------------------------------------
def call_appsec_api(code: str) -> str:
    """Send code to the AppSec scanning API and return raw LLM response."""
    url = f"{APPSEC_API_URL.rstrip('/')}/scan/fast"

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" and parsed.hostname not in _LOCALHOST_HOSTS:
        raise RuntimeError("APPSEC_API_URL must use HTTPS (except localhost).")

    response = httpx.post(
        url,
        json={"code": code, "mode": SCAN_MODE},
        headers={"Authorization": get_auth_header()},
        timeout=120.0,
    )
    response.raise_for_status()
    return response.json()["raw_response"]


def parse_findings(raw: str) -> list[dict]:
    """Extract the JSON findings array from the LLM response."""
    match = re.search(r"```json([\s\S]*?)```", raw, re.MULTILINE)
    if not match:
        logger.warning("No JSON block found in LLM response")
        return []

    try:
        findings = json.loads(match.group(1))
    except json.JSONDecodeError as exc:
        snippet = match.group(1)[:200]
        logger.warning("Failed to parse JSON: %s\nContent: %s", exc, snippet)
        return []

    # Filter out findings with invalid CWEs (same as production pipeline)
    return [f for f in findings if f.get("cwe") and f.get("cwe") != 0]


def format_findings(
    findings: list[dict],
    filename: str,
    file_path: str = "",
    line_map: dict[int, tuple[str, int]] | None = None,
    changed_files: list[str] | None = None,
    suppression_summary: dict | None = None,
) -> str:
    """Format findings as compact plain text optimized for LLM consumption.

    No markdown decoration, emojis, or formatting — just the data Claude
    needs to understand and act on the results. Minimizes token usage.
    """
    suppressed_count = (suppression_summary or {}).get("suppressed", 0)

    header_suffix = ""
    if changed_files is not None:
        header_suffix = f" ({len(changed_files)} file(s))"

    if not findings and not suppressed_count:
        return f"SCAN {filename}{header_suffix}: clean, no findings."
    if not findings and suppressed_count:
        by_inline = (suppression_summary or {}).get("by_inline", 0)
        by_armisignore = suppressed_count - by_inline
        if by_inline and by_armisignore:
            return (
                f"SCAN {filename}{header_suffix}: 0 finding(s) "
                f"({by_armisignore} suppressed by .armisignore, "
                f"{by_inline} by armis:ignore inline)"
            )
        elif by_inline:
            return (
                f"SCAN {filename}{header_suffix}: "
                f"0 finding(s) ({by_inline} suppressed by armis:ignore inline)"
            )
        return (
            f"SCAN {filename}{header_suffix}: "
            f"0 finding(s) ({suppressed_count} suppressed by .armisignore)"
        )

    severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings = sorted(findings, key=lambda f: severity_rank.get(f.get("severity", "").upper(), 99))

    # Header with suppression info when applicable
    if suppressed_count:
        header = (
            f"SCAN {filename}{header_suffix}: {len(findings)} finding(s) "
            f"({len(findings)} active, {suppressed_count} suppressed)"
        )
    else:
        header = f"SCAN {filename}{header_suffix}: {len(findings)} finding(s)"
    lines = [header]

    source_line_to_files: dict[int, list[str]] = {}
    if line_map:
        for _blob, (mfile, src_line) in line_map.items():
            source_line_to_files.setdefault(src_line, [])
            if mfile not in source_line_to_files[src_line]:
                source_line_to_files[src_line].append(mfile)

    for i, f in enumerate(findings):
        severity = f.get("severity", "unknown").upper()
        cwe = f.get("cwe", "?")
        cwe_name = f.get("cwe_name", "")
        raw_line = f.get("line", "?")
        try:
            line_num = int(raw_line)
        except (TypeError, ValueError):
            line_num = None
        explanation = f.get("explanation", "")
        has_secret = f.get("has_secret", False)
        tainted = f.get("tainted_function_references", [])

        cwe_label = f" ({cwe_name})" if cwe_name else ""

        if line_map and line_num is not None and line_num in line_map:
            mapped_file, mapped_line = line_map[line_num]
            location = f"{mapped_file}:{mapped_line}"
        elif line_map and line_num is not None and line_num in source_line_to_files:
            files = source_line_to_files[line_num]
            if len(files) == 1:
                location = f"{files[0]}:{line_num}"
            else:
                location = f"L{raw_line}"
        elif file_path and line_num is not None:
            location = f"{file_path}:{line_num}"
        else:
            location = f"L{raw_line}"

        parts = [f"[{i + 1}] {severity} CWE-{cwe}{cwe_label} {location}: {explanation}"]
        if has_secret:
            parts[0] += " [SECRET]"
        if tainted:
            parts.append(f"    tainted: {', '.join(tainted)}")

        lines.extend(parts)

    # Append suppression summary line
    if suppressed_count:
        by_directive = (suppression_summary or {}).get("by_directive", {})
        by_inline = (suppression_summary or {}).get("by_inline", 0)
        parts = [f"{count} by {d}" for d, count in by_directive.items()]
        if by_inline:
            parts.append(f"{by_inline} by armis:ignore inline")
        lines.append(f"[{suppressed_count} finding(s) suppressed: {', '.join(parts)}]")

    return "\n".join(lines)


_MAX_DIFF_LINES = 50_000


def build_diff_line_map(
    diff_text: str,
) -> tuple[dict[int, tuple[str, int]], list[str]]:
    """Parse unified diff and map blob line numbers to (file_path, source_line).

    Returns (line_map, changed_files) where line_map maps 1-based blob line
    numbers to (file_path, source_line_number) tuples.
    """
    line_map: dict[int, tuple[str, int]] = {}
    changed_files: list[str] = []
    current_file = ""
    current_source_line = 0

    hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

    lines = diff_text.splitlines()
    if len(lines) > _MAX_DIFF_LINES:
        lines = lines[:_MAX_DIFF_LINES]

    for blob_line_num, line in enumerate(lines, start=1):
        if line.startswith("+++ b/"):
            current_file = line[6:]
            if current_file not in changed_files:
                changed_files.append(current_file)
        elif line.startswith("--- ") or line.startswith("diff --git"):
            continue
        elif m := hunk_re.match(line):
            current_source_line = int(m.group(1))
        elif line.startswith("+"):
            if current_file:
                line_map[blob_line_num] = (current_file, current_source_line)
            current_source_line += 1
        elif line.startswith(" "):
            if current_file:
                line_map[blob_line_num] = (current_file, current_source_line)
            current_source_line += 1
        elif line.startswith("-"):
            pass  # removed lines: no mapping, no source line increment

    return line_map, changed_files
