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

# Bound the CWEs accumulated from a single inline directive. A real directive
# lists a handful (the path-read CWE family is the widest at 4: 22/23/73/770),
# so this is generous; it just stops a pathological comment line with thousands
# of `cwe:` tokens from growing an unbounded list. Mirrors _MAX_ARMISIGNORE_LINES.
_MAX_INLINE_CWES = 64


@dataclass(frozen=True)
class InlineDirective:
    category: str | None = None
    # Multiple cwe: tokens accumulate and match with OR logic (any listed CWE
    # suppresses), mirroring .armisignore's `cwes` list and production inline.go.
    # The fast-scan model is non-deterministic about which CWE it assigns to a
    # given sink (e.g. command injection rotates between CWE-78 and CWE-77), so a
    # single directive must be able to name every CWE the finding may surface as.
    # A tuple (not list) keeps this frozen dataclass immutable and hashable.
    cwes: tuple[int, ...] = ()
    severity: str | None = None
    reason: str | None = None
    is_bare: bool = False


def _get_comment_prefixes(file_path: str) -> list[str]:
    """Return comment prefixes for a file based on its extension."""
    ext = os.path.splitext(file_path)[1].lower()
    return _COMMENT_PREFIXES.get(ext, ["#", "//"])


def _find_comment_start(line: str, prefixes: list[str]) -> tuple[int, str] | None:
    """Index + prefix of the first comment marker that is OUTSIDE a string literal.

    Single left-to-right scan tracking ', ", and ` quote state with backslash
    escapes. Returns None when every comment marker sits inside a string (or
    there is none).

    String-awareness is the FAIL-SAFE direction for a suppression parser: a
    marker smuggled into a string literal (e.g. ``q = "... #armis:ignore" + x``)
    must not start a directive, so the finding on that line stays ACTIVE rather
    than being silently suppressed. This is a heuristic, not a full per-language
    tokenizer; any ambiguity it can't resolve leaves the finding active.
    """
    quote: str | None = None
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if quote is not None:
            # Inside a string literal: only a backslash-escape or the matching
            # closing quote matters; comment markers here are just data.
            if ch == "\\":
                i += 2  # skip the escaped character
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            continue
        for prefix in prefixes:
            if line.startswith(prefix, i):
                return i, prefix
        i += 1
    return None


def _extract_comment_text(line: str, prefixes: list[str]) -> str | None:
    """Extract text from the comment portion of a line. Returns None if no comment.

    String-literal aware (see ``_find_comment_start``): a comment marker inside a
    quoted string does not start a comment, so a directive hidden in a string
    literal cannot suppress a finding.
    """
    found = _find_comment_start(line, prefixes)
    if found is None:
        return None
    idx, prefix = found
    if prefix == "<!--":
        end = line.find("-->", idx + 4)
        if end != -1:
            return line[idx + 4 : end].strip()
        return None
    if prefix == "/*":
        end = line.find("*/", idx + 2)
        if end != -1:
            return line[idx + 2 : end].strip()
        return None
    return line[idx + len(prefix) :].strip()


def _parse_inline_directive(text: str) -> InlineDirective | None:
    """Parse an armis:ignore directive from comment text. Flexible param ordering."""
    match = _ARMIS_IGNORE_RE.search(text)
    if not match:
        return None

    remainder = text[match.end() :].strip()
    if not remainder:
        return InlineDirective(is_bare=True)

    category = None
    cwes: list[int] = []
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
                continue
            # Accumulate (OR-match), preserving order and dropping duplicates so
            # `cwe:78 cwe:77` suppresses a finding reported as EITHER CWE. Bounded
            # by _MAX_INLINE_CWES so a pathological line can't grow the list without
            # limit (CWE-770).
            if cwe not in cwes and len(cwes) < _MAX_INLINE_CWES:
                cwes.append(cwe)
        elif lower.startswith("severity:"):
            severity = token[9:]
        elif lower.startswith("rule:"):
            has_rule_only = True

    if not any([category, cwes, severity]):
        if has_rule_only:
            return InlineDirective(reason=reason)
        return InlineDirective(is_bare=True, reason=reason)

    return InlineDirective(category=category, cwes=tuple(cwes), severity=severity, reason=reason)


def _finding_matches_inline(finding: dict, directive: InlineDirective) -> bool:
    """Check if a finding matches an inline directive.

    AND logic *across* param types (cwe / severity / category all specified must
    all hold), but OR logic *within* the cwe list — a finding matches if its CWE
    is any one of the listed CWEs. This mirrors .armisignore and production
    inline.go, and is what makes `cwe:78 cwe:77` suppress an either-way finding.
    """
    if directive.is_bare:
        return True
    if not any([directive.category, directive.cwes, directive.severity]):
        return False

    if directive.cwes:
        if finding.get("cwe") not in directive.cwes:
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


def apply_inline_suppressions_to_diff(
    findings: list[dict],
    diff_text: str,
    line_map: dict[int, tuple[str, int]],
) -> tuple[list[dict], list[dict]]:
    """Apply inline armis:ignore comments to diff-scan findings.

    Findings carry ``line`` = 1-based BLOB line number (the line within
    ``diff_text``), NOT a source-file line. We match directives against the diff
    blob directly, which is correct even when the working tree differs from what
    was scanned (staged / ref scans).

    ``line_map`` (from ``scanner_core.build_diff_line_map``) maps blob line ->
    (file_path, source_line). We REUSE it as the authoritative "is this a content
    line" classifier instead of re-parsing the diff: only added (``+``) and
    context (`` ``) lines are keys, so metadata and removed (``-``) lines are
    excluded automatically. The "line above" check uses source coordinates -- the
    blob line for the SAME file's previous source line -- so it can never bridge a
    hunk gap or a file boundary and falsely suppress a finding.

    Returns (active, suppressed). Fail-open: any error leaves all findings active.
    """
    if not findings:
        return findings, []

    try:
        raw_lines = diff_text.splitlines()
        # Reverse index (file, source_line) -> blob_line, built once.
        src_to_blob: dict[tuple[str, int], int] = {
            (mfile, sline): blob for blob, (mfile, sline) in line_map.items()
        }

        active: list[dict] = []
        suppressed: list[dict] = []

        for finding in findings:
            blob = finding.get("line")
            # Non-int line, or a blob line that is not added/context content
            # (metadata or removed line) -> never suppressible inline.
            if not isinstance(blob, int) or blob not in line_map:
                active.append(finding)
                continue

            mapped_file, src_line = line_map[blob]
            prefixes = _get_comment_prefixes(mapped_file)

            # The finding's own blob line, then the blob line for the same file's
            # previous source line (the "line above" in source coordinates).
            candidate_blobs = [blob]
            above = src_to_blob.get((mapped_file, src_line - 1))
            if above is not None:
                candidate_blobs.append(above)

            matched = False
            for cb in candidate_blobs:
                # Every mapped line starts with '+' or ' '; strip the diff marker.
                line_text = raw_lines[cb - 1][1:]
                comment_text = _extract_comment_text(line_text, prefixes)
                if comment_text and _ARMIS_IGNORE_RE.search(comment_text):
                    directive = _parse_inline_directive(comment_text)
                    if directive and _finding_matches_inline(finding, directive):
                        finding["_suppression_source"] = "inline"
                        finding["_suppressed_by"] = comment_text.strip()
                        suppressed.append(finding)
                        matched = True
                        break

            if not matched:
                active.append(finding)

        return active, suppressed
    except Exception:
        # Fail-open: never lose findings due to a diff-parse error.
        return findings, []
