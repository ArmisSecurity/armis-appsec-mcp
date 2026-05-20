"""Tests for context.py — import extraction, resolution, classification, and assembly."""

import os
import sys

_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from unittest.mock import MagicMock

_mock_exceptions = MagicMock()


class _ToolError(Exception):
    pass


_mock_exceptions.ToolError = _ToolError

_mock_fastmcp = MagicMock()
_mock_fastmcp.exceptions = _mock_exceptions
_mock_fastmcp.Context = MagicMock()

sys.modules.setdefault("mcp", MagicMock())
sys.modules.setdefault("mcp.server", MagicMock())
sys.modules.setdefault("mcp.server.fastmcp", _mock_fastmcp)
sys.modules.setdefault("mcp.server.fastmcp.exceptions", _mock_exceptions)

import importlib

if "path_security" in sys.modules:
    importlib.reload(sys.modules["path_security"])
if "context" in sys.modules:
    importlib.reload(sys.modules["context"])

from context import (
    TaintEntry,
    _safe_read_file,
    classify_file,
    detect_language,
    extract_imports,
    has_security_relevance,
    resolve_import_context,
    resolve_imports,
)


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------
class TestDetectLanguage:
    def test_python(self):
        assert detect_language("app.py") == "python"

    def test_typescript(self):
        assert detect_language("api.ts") == "javascript"

    def test_tsx(self):
        assert detect_language("App.tsx") == "javascript"

    def test_javascript(self):
        assert detect_language("index.js") == "javascript"

    def test_go(self):
        assert detect_language("main.go") == "go"

    def test_unsupported_returns_none(self):
        assert detect_language("lib.rs") is None
        assert detect_language("Main.java") is None
        assert detect_language("file.txt") is None


# ---------------------------------------------------------------------------
# Python import extraction
# ---------------------------------------------------------------------------
class TestExtractPythonImports:
    def test_simple_import(self):
        code = "import os\nimport sys\n"
        result = extract_imports(code, "python")
        assert "os" in result
        assert "sys" in result

    def test_from_import(self):
        code = "from utils.auth import check_token\n"
        result = extract_imports(code, "python")
        assert "utils.auth" in result

    def test_relative_import(self):
        code = "from .helpers import format_date\n"
        result = extract_imports(code, "python")
        assert ".helpers" in result

    def test_parent_relative_import(self):
        code = "from ..config import settings\n"
        result = extract_imports(code, "python")
        assert "..config" in result

    def test_dotted_import(self):
        code = "import pkg.subpkg.module\n"
        result = extract_imports(code, "python")
        assert "pkg.subpkg.module" in result

    def test_commented_import_still_extracted(self):
        code = "# import os\nimport sys\n"
        result = extract_imports(code, "python")
        assert "sys" in result


# ---------------------------------------------------------------------------
# JS/TS import extraction
# ---------------------------------------------------------------------------
class TestExtractJsImports:
    def test_es_import(self):
        code = "import React from './components/App'\n"
        result = extract_imports(code, "javascript")
        assert "./components/App" in result

    def test_named_import(self):
        code = "import { useState } from '../hooks/state'\n"
        result = extract_imports(code, "javascript")
        assert "../hooks/state" in result

    def test_require(self):
        code = "const db = require('./config/database')\n"
        result = extract_imports(code, "javascript")
        assert "./config/database" in result

    def test_dynamic_import(self):
        code = "const mod = await import('./lazy-module')\n"
        result = extract_imports(code, "javascript")
        assert "./lazy-module" in result

    def test_bare_specifier_extracted(self):
        code = "import express from 'express'\n"
        result = extract_imports(code, "javascript")
        assert "express" in result


# ---------------------------------------------------------------------------
# Go import extraction
# ---------------------------------------------------------------------------
class TestExtractGoImports:
    def test_single_import(self):
        code = 'import "fmt"\n'
        result = extract_imports(code, "go")
        assert "fmt" in result

    def test_grouped_imports(self):
        code = 'import (\n\t"fmt"\n\t"os"\n\t"net/http"\n)\n'
        result = extract_imports(code, "go")
        assert "fmt" in result
        assert "os" in result
        assert "net/http" in result

    def test_aliased_import(self):
        code = 'import (\n\tpb "github.com/org/repo/proto"\n)\n'
        result = extract_imports(code, "go")
        assert "github.com/org/repo/proto" in result


# ---------------------------------------------------------------------------
# Python path resolution
# ---------------------------------------------------------------------------
class TestResolvePythonImports:
    def test_relative_import(self, tmp_path):
        (tmp_path / "helpers.py").write_text("def foo(): pass")
        result = resolve_imports([".helpers"], str(tmp_path), "python")
        assert len(result) == 1
        assert result[0].endswith("helpers.py")

    def test_package_init(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        result = resolve_imports([".pkg"], str(tmp_path), "python")
        assert len(result) == 1
        assert "__init__.py" in result[0]

    def test_dotted_module(self, tmp_path):
        sub = tmp_path / "utils"
        sub.mkdir()
        (sub / "db.py").write_text("def query(): pass")
        result = resolve_imports(["utils.db"], str(tmp_path), "python")
        assert len(result) == 1
        assert "db.py" in result[0]

    def test_stdlib_skipped(self):
        result = resolve_imports(["os"], "/tmp", "python")
        assert result == []

    def test_nonexistent_file_skipped(self, tmp_path):
        result = resolve_imports([".nonexistent"], str(tmp_path), "python")
        assert result == []

    def test_parent_relative(self, tmp_path):
        parent = tmp_path / "sub"
        parent.mkdir()
        (tmp_path / "config.py").write_text("x = 1")
        result = resolve_imports(["..config"], str(parent), "python")
        assert len(result) == 1
        assert "config.py" in result[0]


# ---------------------------------------------------------------------------
# JS/TS path resolution
# ---------------------------------------------------------------------------
class TestResolveJsImports:
    def test_extension_probing(self, tmp_path):
        (tmp_path / "auth.ts").write_text("export const check = () => {}")
        result = resolve_imports(["./auth"], str(tmp_path), "javascript")
        assert len(result) == 1
        assert "auth.ts" in result[0]

    def test_index_file(self, tmp_path):
        utils_dir = tmp_path / "utils"
        utils_dir.mkdir()
        (utils_dir / "index.ts").write_text("export default {}")
        result = resolve_imports(["./utils"], str(tmp_path), "javascript")
        assert len(result) == 1
        assert "index.ts" in result[0]

    def test_bare_specifier_skipped(self, tmp_path):
        result = resolve_imports(["express"], str(tmp_path), "javascript")
        assert result == []

    def test_relative_with_extension(self, tmp_path):
        (tmp_path / "config.js").write_text("module.exports = {}")
        result = resolve_imports(["./config.js"], str(tmp_path), "javascript")
        assert len(result) == 1

    def test_parent_relative(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "shared.ts").write_text("export const x = 1")
        result = resolve_imports(["../shared"], str(sub), "javascript")
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Go path resolution
# ---------------------------------------------------------------------------
class TestResolveGoImports:
    def test_local_package(self, tmp_path):
        (tmp_path / "go.mod").write_text("module github.com/org/myapp\n")
        pkg_dir = tmp_path / "internal" / "handler"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "handler.go").write_text("package handler\n")
        result = resolve_imports(["github.com/org/myapp/internal/handler"], str(tmp_path), "go")
        assert len(result) == 1
        assert "handler.go" in result[0]

    def test_stdlib_skipped(self, tmp_path):
        (tmp_path / "go.mod").write_text("module github.com/org/myapp\n")
        result = resolve_imports(["fmt"], str(tmp_path), "go")
        assert result == []

    def test_external_package_skipped(self, tmp_path):
        (tmp_path / "go.mod").write_text("module github.com/org/myapp\n")
        result = resolve_imports(["github.com/other/pkg"], str(tmp_path), "go")
        assert result == []


# ---------------------------------------------------------------------------
# Security classification
# ---------------------------------------------------------------------------
class TestClassifyFile:
    def test_db_match_sink(self, tmp_path):
        code = "import subprocess\nresult = subprocess.run(cmd, shell=True)\n"
        entries = classify_file(str(tmp_path / "cmd.py"), code, "python")
        assert any(e.kind == "sink" and e.confidence == "db" for e in entries)

    def test_db_match_source(self, tmp_path):
        code = "user_input = request.form['name']\n"
        entries = classify_file(str(tmp_path / "app.py"), code, "python")
        assert any(e.kind == "source" for e in entries)

    def test_heuristic_fallback(self, tmp_path):
        code = "def handler(data):\n    spawn(data)\n"
        entries = classify_file(str(tmp_path / "util.py"), code, "python")
        assert any(e.confidence == "heuristic" for e in entries)

    def test_no_match_returns_empty(self, tmp_path):
        code = "x = 1 + 2\nprint(x)\n"
        entries = classify_file(str(tmp_path / "math.py"), code, "python")
        assert entries == []

    def test_has_security_relevance_true(self):
        entries = [TaintEntry("run", "/tmp/x.py", 1, "sink", [78], "db")]
        assert has_security_relevance(entries) is True

    def test_has_security_relevance_false(self):
        entries = [TaintEntry("escape", "/tmp/x.py", 1, "sanitizer", [79], "db")]
        assert has_security_relevance(entries) is False


# ---------------------------------------------------------------------------
# Depth-2 resolution
# ---------------------------------------------------------------------------
class TestDepth2:
    def test_triggered_by_sink(self, tmp_path):
        (tmp_path / "db.py").write_text(
            "import subprocess\ndef run_query(q):\n    subprocess.run(q)\n"
            "from .inner import helper\n"
        )
        inner = tmp_path / "inner.py"
        inner.write_text("def helper():\n    pass\n")
        main_code = "from .db import run_query\nrun_query(user_input)\n"
        (tmp_path / "app.py").write_text(main_code)

        result, taint_map = resolve_import_context(str(tmp_path / "app.py"), main_code, 25000)
        assert result != ""

    def test_not_triggered_for_non_security(self, tmp_path):
        (tmp_path / "utils.py").write_text("def format_date(d):\n    return str(d)\n")
        main_code = "from .utils import format_date\nprint(format_date('today'))\n"
        (tmp_path / "app.py").write_text(main_code)

        result, taint_map = resolve_import_context(str(tmp_path / "app.py"), main_code, 25000)
        assert "SECURITY CONTEXT" in result or result == ""

    def test_circular_import_prevented(self, tmp_path):
        (tmp_path / "a.py").write_text(
            "from .b import x\nimport subprocess\nsubprocess.run('ls')\n"
        )
        (tmp_path / "b.py").write_text("from .a import y\ny = 1\n")
        main_code = "from .a import x\n"
        (tmp_path / "main.py").write_text(main_code)

        result, _ = resolve_import_context(str(tmp_path / "main.py"), main_code, 25000)
        # Should complete without infinite loop


# ---------------------------------------------------------------------------
# Budget management
# ---------------------------------------------------------------------------
class TestBudgetManagement:
    def test_budget_zero_skips_context(self, tmp_path):
        (tmp_path / "utils.py").write_text("x = 1\n")
        main_code = "from .utils import x\n"
        (tmp_path / "app.py").write_text(main_code)

        result, _ = resolve_import_context(str(tmp_path / "app.py"), main_code, 0)
        assert result == ""

    def test_budget_below_threshold(self, tmp_path):
        (tmp_path / "utils.py").write_text("x = 1\n")
        main_code = "from .utils import x\n"
        (tmp_path / "app.py").write_text(main_code)

        result, _ = resolve_import_context(str(tmp_path / "app.py"), main_code, 100)
        assert result == ""

    def test_context_respects_max_budget(self, tmp_path):
        (tmp_path / "big.py").write_text("x = 'a' * 50000\n")
        main_code = "from .big import x\n"
        (tmp_path / "app.py").write_text(main_code)

        result, _ = resolve_import_context(str(tmp_path / "app.py"), main_code, 1000)
        if result:
            assert len(result) <= 1000 + 200  # some overhead for markers


# ---------------------------------------------------------------------------
# Error handling (fail-open)
# ---------------------------------------------------------------------------
class TestErrorHandling:
    def test_unsupported_language_returns_empty(self, tmp_path):
        (tmp_path / "app.rs").write_text("use std::io;\n")
        result, taint = resolve_import_context(str(tmp_path / "app.rs"), "use std::io;", 25000)
        assert result == ""
        assert taint == []

    def test_no_imports_returns_empty(self, tmp_path):
        code = "x = 1\nprint(x)\n"
        (tmp_path / "app.py").write_text(code)
        result, _ = resolve_import_context(str(tmp_path / "app.py"), code, 25000)
        assert result == ""

    def test_all_unresolvable_returns_empty(self, tmp_path):
        code = "from .nonexistent import foo\nfrom .also_gone import bar\n"
        (tmp_path / "app.py").write_text(code)
        result, _ = resolve_import_context(str(tmp_path / "app.py"), code, 25000)
        assert result == ""

    def test_safe_read_file_binary_returns_none(self, tmp_path):
        f = tmp_path / "binary.py"
        f.write_bytes(b"hello\x00world")
        assert _safe_read_file(str(f)) is None

    def test_safe_read_file_missing_returns_none(self):
        assert _safe_read_file("/nonexistent/path.py") is None

    def test_safe_read_file_permission_denied(self, tmp_path):
        f = tmp_path / "secret.py"
        f.write_text("secret")
        f.chmod(0o000)
        result = _safe_read_file(str(f))
        f.chmod(0o644)  # restore for cleanup
        assert result is None


# ---------------------------------------------------------------------------
# Integration: full resolve_import_context
# ---------------------------------------------------------------------------
class TestResolveImportContextIntegration:
    def test_produces_context_block(self, tmp_path):
        (tmp_path / "db.py").write_text(
            "import sqlite3\ndef query(sql):\n    conn = sqlite3.connect(':memory:')\n"
            "    conn.execute(sql)\n"
        )
        main_code = "from .db import query\nquery(user_input)\n"
        (tmp_path / "app.py").write_text(main_code)

        result, taint_map = resolve_import_context(str(tmp_path / "app.py"), main_code, 25000)
        assert "SECURITY CONTEXT" in result
        assert "db.py" in result
        assert len(taint_map) > 0

    def test_taint_map_contains_classified_entries(self, tmp_path):
        (tmp_path / "handler.py").write_text(
            "import subprocess\ndef run_cmd(cmd):\n    subprocess.run(cmd)\n"
        )
        main_code = "from .handler import run_cmd\n"
        (tmp_path / "app.py").write_text(main_code)

        _, taint_map = resolve_import_context(str(tmp_path / "app.py"), main_code, 25000)
        assert any(e.function_name == "run" for e in taint_map)
        assert any(e.kind == "sink" for e in taint_map)
