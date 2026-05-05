"""
.armisignore file parser and finding suppression logic.

Reads suppression directives from {git_root}/.armisignore and applies them
to scan findings. Also handles inline armis:ignore comment detection.
Fail-open: any parse/IO error leaves findings active.
"""

import fnmatch
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger("appsec-mcp")

_MAX_ARMISIGNORE_LINES = 1000


@dataclass
class ArmisIgnoreConfig:
    file_patterns: list[str] = field(default_factory=list)
    cwes: list[int] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)


def find_git_root(from_path: str | None = None) -> str | None:
    """Return the git repository root, or None if not in a git repo.

    Re-resolved on every call to handle long-running server processes
    where the user may switch between repositories.
    """
    cwd = os.path.dirname(from_path) if from_path and os.path.isabs(from_path) else None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=cwd,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def load_armisignore(git_root: str | None) -> ArmisIgnoreConfig:
    """Read and parse .armisignore from git root. Returns empty config on failure."""
    if not git_root:
        return ArmisIgnoreConfig()
    path = os.path.join(git_root, ".armisignore")
    try:
        with open(path, encoding="utf-8-sig") as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return ArmisIgnoreConfig()
    return _parse_armisignore_lines(lines)


def _parse_armisignore_lines(lines: list[str]) -> ArmisIgnoreConfig:
    """Parse .armisignore lines into config. Pure logic, no I/O."""
    if len(lines) > _MAX_ARMISIGNORE_LINES:
        logger.warning(
            ".armisignore has %d lines, truncating to %d",
            len(lines),
            _MAX_ARMISIGNORE_LINES,
        )
        lines = lines[:_MAX_ARMISIGNORE_LINES]

    config = ArmisIgnoreConfig()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Strip inline reason: "cwe:798 -- hardcoded creds"
        if " -- " in line:
            line = line.split(" -- ", 1)[0].strip()

        if line.startswith("cwe:"):
            value = line[4:]
            try:
                config.cwes.append(int(value))
            except ValueError:
                logger.warning(".armisignore: invalid cwe directive: %r", line)
        elif line.startswith("severity:"):
            config.severities.append(line[9:].strip().upper())
        elif line.startswith("category:"):
            config.categories.append(line[9:].strip().lower())
        elif line.startswith("rule:"):
            config.rule_ids.append(line[5:].strip())
        else:
            if line in ("*", "**", "**/*"):
                logger.warning(
                    ".armisignore: broad pattern %r may exclude all files from scanning",
                    line,
                )
            config.file_patterns.append(line)

    return config


def _fnmatch_gitignore(path: str, pattern: str) -> bool:
    """Match path against pattern using .gitignore-style semantics.

    Unlike fnmatch.fnmatch, '*' does NOT cross '/' boundaries.
    '**' matches zero or more path segments (like .gitignore).
    """
    path_parts = path.split("/")
    pattern_parts = pattern.split("/")
    return _match_parts(path_parts, pattern_parts)


def _match_parts(path_parts: list[str], pattern_parts: list[str]) -> bool:
    """Recursively match path segments against pattern segments."""
    pi = 0  # path index
    pa = 0  # pattern index

    while pa < len(pattern_parts):
        if pi >= len(path_parts):
            # Remaining pattern segments must all be ** to match
            if all(p == "**" for p in pattern_parts[pa:]):
                return True
            return False

        if pattern_parts[pa] == "**":
            # ** matches zero or more path segments
            if pa == len(pattern_parts) - 1:
                return True
            # Try matching remaining pattern against each suffix of path
            for i in range(pi, len(path_parts)):
                if _match_parts(path_parts[i:], pattern_parts[pa + 1 :]):
                    return True
            return False

        # Single segment: use fnmatch but only within this segment (no / possible)
        if not fnmatch.fnmatch(path_parts[pi], pattern_parts[pa]):
            return False

        pi += 1
        pa += 1

    return pi == len(path_parts)


def is_path_excluded(file_path: str, config: ArmisIgnoreConfig, git_root: str) -> bool:
    """Check if a file path matches any exclusion pattern in the config.

    Uses .gitignore-style semantics: '*' does not cross '/', '**' matches
    zero or more directories. Trailing-slash patterns match directory prefixes.
    """
    if not config.file_patterns:
        return False

    rel_path = os.path.relpath(file_path, git_root)
    # Normalize to forward slashes for consistent matching
    rel_path = rel_path.replace(os.sep, "/")

    for pattern in config.file_patterns:
        if pattern.endswith("/"):
            # Directory prefix match
            prefix = pattern  # e.g. "vendor/"
            if rel_path.startswith(prefix) or rel_path == prefix.rstrip("/"):
                return True
        elif "/" in pattern:
            # Pattern contains path separator — match against full relative path
            if _fnmatch_gitignore(rel_path, pattern):
                return True
        else:
            # No path separator — match against basename (like .gitignore)
            if fnmatch.fnmatch(os.path.basename(rel_path), pattern):
                return True

    return False


def _derive_category(finding: dict) -> str:
    """Derive category from finding fields: has_secret=True → "secrets", else "sast"."""
    return "secrets" if finding.get("has_secret") else "sast"


def _finding_matches_config(finding: dict, config: ArmisIgnoreConfig) -> str | None:
    """Check if a finding matches any directive in config (OR logic).

    Returns the first matching directive string, or None if no match.

    Priority order (first match wins for attribution):
      1. CWE   — most specific (e.g., "cwe:798")
      2. Severity — medium specificity (e.g., "severity:LOW")
      3. Category — broadest (e.g., "category:secrets")

    A finding matching multiple directives is suppressed regardless of which
    is returned; the return value only affects the by_directive summary.
    rule: directives are silently skipped (fast-scan model has no rule ID).
    """
    # CWE match
    finding_cwe = finding.get("cwe")
    if finding_cwe and finding_cwe in config.cwes:
        return f"cwe:{finding_cwe}"

    # Severity match
    finding_severity = (finding.get("severity") or "").upper()
    if finding_severity and finding_severity in config.severities:
        return f"severity:{finding_severity}"

    # Category match
    finding_category = _derive_category(finding)
    if finding_category in config.categories:
        return f"category:{finding_category}"

    return None


def apply_suppressions(
    findings: list[dict], config: ArmisIgnoreConfig
) -> tuple[list[dict], list[dict], dict]:
    """Apply .armisignore directives to findings.

    Returns:
        (active, suppressed, summary) where summary is:
        {"total": N, "active": X, "suppressed": Y, "by_directive": {"cwe:798": 2, ...}}
    """
    if not findings or _is_empty_config(config):
        return (
            findings,
            [],
            {"total": len(findings), "active": len(findings), "suppressed": 0, "by_directive": {}},
        )

    active = []
    suppressed = []
    by_directive: dict[str, int] = {}

    for finding in findings:
        directive = _finding_matches_config(finding, config)
        if directive:
            finding["_suppression_source"] = "armisignore"
            finding["_suppressed_by"] = directive
            suppressed.append(finding)
            by_directive[directive] = by_directive.get(directive, 0) + 1
        else:
            active.append(finding)

    summary = {
        "total": len(findings),
        "active": len(active),
        "suppressed": len(suppressed),
        "by_directive": by_directive,
    }
    return active, suppressed, summary


def filter_diff_excluded_paths(diff_text: str, config: ArmisIgnoreConfig, git_root: str) -> str:
    """Remove diff sections for files excluded by .armisignore path patterns.

    Splits unified diff on 'diff --git' boundaries, checks each file path
    against is_path_excluded(), and returns the rejoined diff without excluded
    sections. Preamble text before the first header is preserved.
    """
    if not config.file_patterns or not diff_text:
        return diff_text

    sections = diff_text.split("diff --git ")
    # sections[0] is preamble (empty or text before first diff header)
    preamble = sections[0]
    kept: list[str] = []

    for section in sections[1:]:
        path = _extract_diff_path(section)
        if path and is_path_excluded(os.path.join(git_root, path), config, git_root):
            logger.info("filter_diff_excluded_paths: excluding %s", path)
            continue
        kept.append(section)

    if not kept:
        return ""

    result = preamble + "diff --git ".join([""] + kept)
    return result


def _extract_diff_path(section: str) -> str | None:
    """Extract the b/ file path from a diff section header.

    Handles both 'a/path b/path' and quoted forms like 'a/"path" b/"path"'.
    For renames, uses the b/ (destination) path.
    """
    first_line = section.split("\n", 1)[0]
    # The header line after 'diff --git ' is: a/old b/new
    # Find the b/ path — it's the last space-separated token starting with b/
    # Handle quoted paths: "b/path with spaces"
    if ' b/"' in first_line:
        start = first_line.index(' b/"') + 3
        end = (
            first_line.index('"', start + 1) + 1
            if '"' in first_line[start + 1 :]
            else len(first_line)
        )
        return first_line[start:end].strip('"')
    elif " b/" in first_line:
        b_idx = first_line.rindex(" b/")
        return first_line[b_idx + 3 :]
    return None


def _is_empty_config(config: ArmisIgnoreConfig) -> bool:
    """Check if config has no finding-level directives (file_patterns/rule_ids irrelevant)."""
    return not (config.cwes or config.severities or config.categories)


# ---------------------------------------------------------------------------
# Inline armis:ignore suppression
# ---------------------------------------------------------------------------

_COMMENT_PREFIXES: dict[str, list[str]] = {
    ".py": ["#"],
    ".rb": ["#"],
    ".sh": ["#"],
    ".bash": ["#"],
    ".zsh": ["#"],
    ".yaml": ["#"],
    ".yml": ["#"],
    ".tf": ["#"],
    ".hcl": ["#"],
    ".toml": ["#"],
    ".r": ["#"],
    ".js": ["//"],
    ".ts": ["//"],
    ".jsx": ["//"],
    ".tsx": ["//"],
    ".java": ["//"],
    ".c": ["//"],
    ".h": ["//"],
    ".cpp": ["//"],
    ".cc": ["//"],
    ".go": ["//"],
    ".rs": ["//"],
    ".swift": ["//"],
    ".kt": ["//"],
    ".kts": ["//"],
    ".scala": ["//"],
    ".dart": ["//"],
    ".groovy": ["//"],
    ".cs": ["//"],
    ".php": ["//", "#"],
    ".sql": ["--"],
    ".lua": ["--"],
    ".hs": ["--"],
    ".ada": ["--"],
    ".ini": [";"],
    ".cfg": [";"],
    ".html": ["<!--"],
    ".xml": ["<!--"],
    ".svg": ["<!--"],
    ".css": ["/*"],
}

_ARMIS_IGNORE_RE = re.compile(r"armis:ignore", re.IGNORECASE)


@dataclass(frozen=True)
class InlineDirective:
    category: str | None = None
    cwe: int | None = None
    severity: str | None = None
    reason: str | None = None
    is_bare: bool = False


def _get_comment_prefixes(file_path: str) -> list[str]:
    """Return comment prefixes for a file based on its extension."""
    ext = os.path.splitext(file_path)[1].lower()
    return _COMMENT_PREFIXES.get(ext, ["#", "//"])


def _extract_comment_text(line: str, prefixes: list[str]) -> str | None:
    """Extract text from the comment portion of a line. Returns None if no comment."""
    for prefix in prefixes:
        if prefix == "<!--":
            start = line.find("<!--")
            if start != -1:
                end = line.find("-->", start + 4)
                if end != -1:
                    return line[start + 4 : end].strip()
        elif prefix == "/*":
            start = line.find("/*")
            if start != -1:
                end = line.find("*/", start + 2)
                if end != -1:
                    return line[start + 2 : end].strip()
        else:
            idx = line.find(prefix)
            if idx != -1:
                return line[idx + len(prefix) :].strip()
    return None


def _parse_inline_directive(text: str) -> InlineDirective | None:
    """Parse an armis:ignore directive from comment text. Flexible param ordering."""
    match = _ARMIS_IGNORE_RE.search(text)
    if not match:
        return None

    remainder = text[match.end() :].strip()
    if not remainder:
        return InlineDirective(is_bare=True)

    category = None
    cwe = None
    severity = None
    reason = None
    has_rule_only = False

    reason_match = re.search(r"\breason:\s*(.+)", remainder, re.IGNORECASE)
    if reason_match:
        reason = reason_match.group(1).strip()
        remainder = remainder[: reason_match.start()].strip()

    for token in remainder.split():
        lower = token.lower()
        if lower.startswith("category:"):
            category = token[9:]
        elif lower.startswith("cwe:"):
            try:
                cwe = int(token[4:])
            except ValueError:
                pass
        elif lower.startswith("severity:"):
            severity = token[9:]
        elif lower.startswith("rule:"):
            has_rule_only = True

    if not any([category, cwe, severity]):
        if has_rule_only:
            return InlineDirective(reason=reason)
        return InlineDirective(is_bare=True, reason=reason)

    return InlineDirective(category=category, cwe=cwe, severity=severity, reason=reason)


def _finding_matches_inline(finding: dict, directive: InlineDirective) -> bool:
    """Check if a finding matches an inline directive (AND logic for specified params)."""
    if directive.is_bare:
        return True
    if not any([directive.category, directive.cwe, directive.severity]):
        return False

    if directive.cwe is not None:
        if finding.get("cwe") != directive.cwe:
            return False
    if directive.severity is not None:
        if (finding.get("severity") or "").upper() != directive.severity.upper():
            return False
    if directive.category is not None:
        if _derive_category(finding) != directive.category.lower():
            return False
    return True


def apply_inline_suppressions(
    findings: list[dict],
    file_path: str,
    source_lines: list[str] | None = None,
) -> tuple[list[dict], list[dict]]:
    """Apply inline armis:ignore comments to findings. Fail-open on any error."""
    if not findings:
        return findings, []

    if source_lines is None:
        try:
            with open(file_path, encoding="utf-8-sig") as f:
                source_lines = f.read().splitlines()
        except (OSError, UnicodeDecodeError):
            return findings, []

    prefixes = _get_comment_prefixes(file_path)
    active: list[dict] = []
    suppressed: list[dict] = []

    for finding in findings:
        line_num = finding.get("line")
        if not isinstance(line_num, int) or line_num < 1 or line_num > len(source_lines):
            active.append(finding)
            continue

        matched = False
        lines_to_check = [line_num - 1]  # 0-indexed: the finding line
        if line_num >= 2:
            lines_to_check.append(line_num - 2)  # line above

        for idx in lines_to_check:
            comment_text = _extract_comment_text(source_lines[idx], prefixes)
            if comment_text and _ARMIS_IGNORE_RE.search(comment_text):
                directive = _parse_inline_directive(comment_text)
                if directive and _finding_matches_inline(finding, directive):
                    raw = comment_text.strip()
                    finding["_suppression_source"] = "inline"
                    finding["_suppressed_by"] = raw
                    suppressed.append(finding)
                    matched = True
                    break

        if not matched:
            active.append(finding)

    return active, suppressed
