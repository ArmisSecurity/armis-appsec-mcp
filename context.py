"""
Cross-file context injection for the Armis AppSec MCP plugin.

Resolves imports from a scanned file, classifies them by security relevance
using the built-in security function database, and assembles a prioritized
context block within the 90k character budget.

Supports Python, JavaScript/TypeScript, and Go (local packages only).
"""

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Literal

from mcp.server.fastmcp.exceptions import ToolError

from path_security import validate_file_path
from security_db import SECURITY_DB

logger = logging.getLogger("armis-appsec-context")

_MIN_CONTEXT_BUDGET = 500
_MAX_CONTEXT_BUDGET = 25_000
_DEPTH2_CAP_PER_IMPORT = 5
_BLAST_RADIUS_FILE_CAP = 500

_LANG_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".go": "go",
}

_HEURISTIC_SINK_PATTERNS = re.compile(
    r"\b(exec|query|eval|write|render|open|system|spawn|execute|popen)\b", re.IGNORECASE
)
_HEURISTIC_SOURCE_PATTERNS = re.compile(
    r"\b(input|request|read|recv|getenv|stdin|argv|form|body|params)\b", re.IGNORECASE
)

# --- Python import regex ---
_PY_IMPORT_RE = re.compile(r"^import\s+(\S+)", re.MULTILINE)
_PY_FROM_IMPORT_RE = re.compile(r"^from\s+(\S+)\s+import\b", re.MULTILINE)

# --- JS/TS import regex ---
_JS_IMPORT_FROM_RE = re.compile(r"""import\s+.*?\s+from\s+['"](.+?)['"]""")
_JS_REQUIRE_RE = re.compile(r"""require\(\s*['"](.+?)['"]\s*\)""")
_JS_DYNAMIC_IMPORT_RE = re.compile(r"""import\(\s*['"](.+?)['"]\s*\)""")

# --- Go import regex ---
_GO_SINGLE_IMPORT_RE = re.compile(r'^import\s+"([^"]+)"', re.MULTILINE)
_GO_GROUPED_IMPORT_RE = re.compile(r"^import\s*\((.*?)\)", re.MULTILINE | re.DOTALL)
_GO_IMPORT_LINE_RE = re.compile(r'(?:\w+\s+)?"([^"]+)"')


@dataclass
class TaintEntry:
    function_name: str
    file_path: str
    line: int
    kind: Literal["source", "sink", "sanitizer"]
    cwe_relevance: list[int] = field(default_factory=list)
    confidence: Literal["db", "heuristic"] = "db"


@dataclass
class CallerInfo:
    file_path: str
    line: int
    context: str


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------


def detect_language(file_path: str) -> str | None:
    ext = os.path.splitext(file_path)[1].lower()
    return _LANG_MAP.get(ext)


# ---------------------------------------------------------------------------
# Import extraction
# ---------------------------------------------------------------------------


def extract_imports(code: str, language: str) -> list[str]:
    if language == "python":
        return _extract_python_imports(code)
    elif language == "javascript":
        return _extract_js_imports(code)
    elif language == "go":
        return _extract_go_imports(code)
    return []


def _extract_python_imports(code: str) -> list[str]:
    results = []
    for m in _PY_IMPORT_RE.finditer(code):
        results.append(m.group(1))
    for m in _PY_FROM_IMPORT_RE.finditer(code):
        results.append(m.group(1))
    return results


def _extract_js_imports(code: str) -> list[str]:
    results = []
    for m in _JS_IMPORT_FROM_RE.finditer(code):
        results.append(m.group(1))
    for m in _JS_REQUIRE_RE.finditer(code):
        results.append(m.group(1))
    for m in _JS_DYNAMIC_IMPORT_RE.finditer(code):
        results.append(m.group(1))
    return results


def _extract_go_imports(code: str) -> list[str]:
    results = []
    for m in _GO_SINGLE_IMPORT_RE.finditer(code):
        results.append(m.group(1))
    for m in _GO_GROUPED_IMPORT_RE.finditer(code):
        block = m.group(1)
        for line_m in _GO_IMPORT_LINE_RE.finditer(block):
            results.append(line_m.group(1))
    return results


# ---------------------------------------------------------------------------
# Import resolution
# ---------------------------------------------------------------------------


def resolve_imports(imports: list[str], base_dir: str, language: str) -> list[str]:
    resolved = []
    for imp in imports:
        path = _resolve_single_import(imp, base_dir, language)
        if path:
            resolved.append(path)
    return resolved


def _resolve_single_import(imp: str, base_dir: str, language: str) -> str | None:
    if language == "python":
        return _resolve_python_import(imp, base_dir)
    elif language == "javascript":
        return _resolve_js_import(imp, base_dir)
    elif language == "go":
        return _resolve_go_import(imp, base_dir)
    return None


def _resolve_python_import(module: str, base_dir: str) -> str | None:
    if module.startswith("."):
        dots = len(module) - len(module.lstrip("."))
        remainder = module[dots:]
        target_dir = base_dir
        for _ in range(dots - 1):
            target_dir = os.path.dirname(target_dir)
        parts = remainder.split(".") if remainder else []
    else:
        if "." not in module:
            return None
        parts = module.split(".")
        target_dir = base_dir

    path = os.path.join(target_dir, *parts)
    candidates = [path + ".py", os.path.join(path, "__init__.py")]
    for candidate in candidates:
        resolved = os.path.realpath(candidate)
        if os.path.isfile(resolved):
            if _is_path_safe(resolved):
                return resolved
    return None


def _resolve_js_import(path_str: str, base_dir: str) -> str | None:
    if not path_str.startswith(("./", "../")):
        return None

    full = os.path.join(base_dir, path_str)
    extensions = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]

    resolved = os.path.realpath(full)
    if os.path.isfile(resolved) and _is_path_safe(resolved):
        return resolved

    for ext in extensions:
        candidate = os.path.realpath(full + ext)
        if os.path.isfile(candidate) and _is_path_safe(candidate):
            return candidate

    index_names = ["index.ts", "index.tsx", "index.js", "index.jsx"]
    for idx in index_names:
        candidate = os.path.realpath(os.path.join(full, idx))
        if os.path.isfile(candidate) and _is_path_safe(candidate):
            return candidate

    return None


def _resolve_go_import(import_path: str, base_dir: str) -> str | None:
    if "/" not in import_path or "." not in import_path.split("/")[0]:
        return None

    go_mod = _find_go_mod(base_dir)
    if not go_mod:
        return None

    module_root = os.path.dirname(go_mod)
    module_prefix = _read_go_module_name(go_mod)
    if not module_prefix:
        return None

    if not import_path.startswith(module_prefix):
        return None

    relative = import_path[len(module_prefix) :]
    if relative.startswith("/"):
        relative = relative[1:]

    pkg_dir = os.path.realpath(os.path.join(module_root, relative))
    if os.path.isdir(pkg_dir) and _is_path_safe(pkg_dir):
        go_files = [
            os.path.join(pkg_dir, f)
            for f in os.listdir(pkg_dir)
            if f.endswith(".go") and not f.endswith("_test.go")
        ]
        if go_files:
            return go_files[0]
    return None


def _find_go_mod(start_dir: str) -> str | None:
    current = os.path.realpath(start_dir)
    for _ in range(20):
        candidate = os.path.join(current, "go.mod")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


def _read_go_module_name(go_mod_path: str) -> str | None:
    try:
        with open(go_mod_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("module "):
                    return line[7:].strip()
    except OSError:
        pass
    return None


def _is_path_safe(resolved: str) -> bool:
    try:
        validate_file_path(resolved)
        return True
    except (ToolError, Exception):
        logger.debug("Path validation rejected: %s", resolved)
        return False


# ---------------------------------------------------------------------------
# Function classification
# ---------------------------------------------------------------------------


def classify_file(file_path: str, content: str, language: str) -> list[TaintEntry]:
    entries = []
    lines = content.splitlines()

    for db_entry in SECURITY_DB:
        if db_entry.language != language:
            continue
        for i, line in enumerate(lines, 1):
            if db_entry.name in line:
                entries.append(
                    TaintEntry(
                        function_name=db_entry.name,
                        file_path=file_path,
                        line=i,
                        kind=db_entry.kind,
                        cwe_relevance=list(db_entry.cwe),
                        confidence="db",
                    )
                )
                break

    if not entries:
        entries = _heuristic_classify(file_path, lines)

    return entries


def _heuristic_classify(file_path: str, lines: list[str]) -> list[TaintEntry]:
    entries = []
    for i, line in enumerate(lines, 1):
        if _HEURISTIC_SINK_PATTERNS.search(line):
            func_match = re.search(r"\b(\w+)\s*\(", line)
            if func_match:
                entries.append(
                    TaintEntry(
                        function_name=func_match.group(1),
                        file_path=file_path,
                        line=i,
                        kind="sink",
                        confidence="heuristic",
                    )
                )
                break
        if _HEURISTIC_SOURCE_PATTERNS.search(line):
            func_match = re.search(r"\b(\w+)\s*[\.(]", line)
            if func_match:
                entries.append(
                    TaintEntry(
                        function_name=func_match.group(1),
                        file_path=file_path,
                        line=i,
                        kind="source",
                        confidence="heuristic",
                    )
                )
                break
    return entries


def has_security_relevance(entries: list[TaintEntry]) -> bool:
    return any(e.kind in ("sink", "source") for e in entries)


# ---------------------------------------------------------------------------
# Context assembly
# ---------------------------------------------------------------------------


@dataclass
class _ResolvedFile:
    path: str
    content: str
    classification: list[TaintEntry]
    priority: int
    depth: int


def resolve_import_context(
    file_path: str, primary_code: str, max_context_chars: int
) -> tuple[str, list[TaintEntry]]:
    """Resolve imports and build security context block.

    Returns (formatted_context_block, taint_map). Empty string if nothing resolved.
    """
    language = detect_language(file_path)
    if not language:
        return "", []

    context_budget = min(_MAX_CONTEXT_BUDGET, max_context_chars)
    if context_budget < _MIN_CONTEXT_BUDGET:
        return "", []

    base_dir = os.path.dirname(os.path.realpath(file_path))
    imports = extract_imports(primary_code, language)
    if not imports:
        return "", []

    resolved_paths = resolve_imports(imports, base_dir, language)
    if not resolved_paths:
        return "", []

    resolved_files: list[_ResolvedFile] = []
    all_taint_entries: list[TaintEntry] = []
    visited = {os.path.realpath(file_path)}

    for rpath in resolved_paths:
        if rpath in visited:
            continue
        visited.add(rpath)

        content = _safe_read_file(rpath)
        if content is None:
            continue

        classification = classify_file(rpath, content, language)
        priority = _compute_priority(classification)
        resolved_files.append(
            _ResolvedFile(
                path=rpath,
                content=content,
                classification=classification,
                priority=priority,
                depth=1,
            )
        )
        all_taint_entries.extend(classification)

    security_relevant_d1 = [
        rf for rf in resolved_files if has_security_relevance(rf.classification)
    ]
    for rf in security_relevant_d1:
        d2_imports = extract_imports(rf.content, language)
        d2_resolved = resolve_imports(d2_imports, os.path.dirname(rf.path), language)
        d2_count = 0
        for d2path in d2_resolved:
            if d2_count >= _DEPTH2_CAP_PER_IMPORT:
                break
            if d2path in visited:
                continue
            visited.add(d2path)

            d2_content = _safe_read_file(d2path)
            if d2_content is None:
                continue

            d2_class = classify_file(d2path, d2_content, language)
            if has_security_relevance(d2_class):
                resolved_files.append(
                    _ResolvedFile(
                        path=d2path,
                        content=d2_content,
                        classification=d2_class,
                        priority=_compute_priority(d2_class) + 10,
                        depth=2,
                    )
                )
                all_taint_entries.extend(d2_class)
                d2_count += 1

    resolved_files.sort(key=lambda rf: (rf.priority, len(rf.content)))
    context_block = _assemble_context(resolved_files, context_budget, all_taint_entries)
    return context_block, all_taint_entries


def _compute_priority(entries: list[TaintEntry]) -> int:
    for e in entries:
        if e.kind == "sink" and e.confidence == "db":
            return 1
        if e.kind == "source" and e.confidence == "db":
            return 2
        if e.kind == "sanitizer":
            return 3
        if e.kind == "sink" and e.confidence == "heuristic":
            return 4
        if e.kind == "source" and e.confidence == "heuristic":
            return 5
    return 99


def _assemble_context(files: list[_ResolvedFile], budget: int, taint_map: list[TaintEntry]) -> str:
    if not files:
        return ""

    taint_header = _format_taint_header(taint_map)
    open_marker = "// === SECURITY CONTEXT (cross-file taint analysis) ===\n"
    close_marker = "// === END SECURITY CONTEXT ===\n"
    header_cost = len(taint_header) + len(open_marker) + len(close_marker)
    remaining = budget - header_cost
    if remaining <= 0:
        return ""

    parts = ["// === SECURITY CONTEXT (cross-file taint analysis) ===\n"]
    parts.append(taint_header)

    for rf in files:
        rel_path = os.path.basename(rf.path)
        kind_label = rf.classification[0].kind.upper() if rf.classification else "NONE"
        file_header = f"// --- file: {rel_path} (priority: {kind_label}, depth: {rf.depth}) ---\n"
        file_footer = "// --- end file ---\n"
        overhead = len(file_header) + len(file_footer)

        available = remaining - overhead
        if available <= 0:
            break

        content = rf.content[:available]
        remaining -= len(file_header) + len(content) + len(file_footer)
        parts.append(file_header)
        parts.append(content)
        if not content.endswith("\n"):
            parts.append("\n")
        parts.append(file_footer)

        if remaining <= 0:
            break

    parts.append("// === END SECURITY CONTEXT ===")
    return "".join(parts)


def _format_taint_header(taint_map: list[TaintEntry]) -> str:
    sources = [e for e in taint_map if e.kind == "source"]
    sinks = [e for e in taint_map if e.kind == "sink"]
    sanitizers = [e for e in taint_map if e.kind == "sanitizer"]

    lines = ["// TAINT MAP:\n"]
    if sources:
        src_strs = [
            f"{e.function_name} ({os.path.basename(e.file_path)}:{e.line})" for e in sources[:5]
        ]
        lines.append(f"//   SOURCES: {', '.join(src_strs)}\n")
    if sinks:
        sink_strs = [
            f"{e.function_name} ({os.path.basename(e.file_path)}:{e.line})" for e in sinks[:5]
        ]
        lines.append(f"//   SINKS: {', '.join(sink_strs)}\n")
    if sanitizers:
        san_strs = [
            f"{e.function_name} ({os.path.basename(e.file_path)}:{e.line})" for e in sanitizers[:5]
        ]
        lines.append(f"//   SANITIZERS: {', '.join(san_strs)}\n")
    lines.append("//\n")
    return "".join(lines)


# ---------------------------------------------------------------------------
# Blast radius resolution
# ---------------------------------------------------------------------------


def resolve_blast_radius(function_name: str, file_path: str) -> list[CallerInfo]:
    """Find all files that import and call the given function."""
    resolved = os.path.realpath(file_path)
    git_root = _find_git_root(resolved)
    if not git_root:
        return []

    tracked_files = _get_tracked_files(git_root)
    if not tracked_files:
        return []

    target_basename = os.path.basename(resolved)
    target_module = os.path.splitext(target_basename)[0]
    callers: list[CallerInfo] = []

    for fpath in tracked_files[:_BLAST_RADIUS_FILE_CAP]:
        full_path = os.path.join(git_root, fpath)
        if os.path.realpath(full_path) == resolved:
            continue

        language = detect_language(fpath)
        if not language:
            continue

        try:
            with open(full_path, encoding="utf-8", errors="replace") as f:
                content = f.read(50_000)
        except OSError:
            continue

        if target_module not in content and target_basename not in content:
            continue

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            if function_name in line and target_module in content:
                callers.append(
                    CallerInfo(
                        file_path=full_path,
                        line=i,
                        context=line.strip()[:120],
                    )
                )
                break

    return callers


def _find_git_root(from_path: str) -> str | None:
    current = os.path.dirname(from_path) if os.path.isfile(from_path) else from_path
    for _ in range(20):
        if os.path.isdir(os.path.join(current, ".git")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


def _get_tracked_files(git_root: str) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=git_root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return []
        files = result.stdout.strip().splitlines()
        supported_exts = set(_LANG_MAP.keys())
        return [f for f in files if os.path.splitext(f)[1].lower() in supported_exts]
    except (subprocess.TimeoutExpired, OSError):
        return []


# ---------------------------------------------------------------------------
# File reading (fail-open)
# ---------------------------------------------------------------------------


def _safe_read_file(path: str, max_bytes: int = 100_000) -> str | None:
    try:
        if not os.path.isfile(path):
            return None
        size = os.path.getsize(path)
        if size > max_bytes:
            return None
        with open(path, "rb") as f:
            if b"\x00" in f.read(8192):
                return None
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except (OSError, PermissionError):
        logger.debug("Failed to read file for context: %s", path)
        return None
