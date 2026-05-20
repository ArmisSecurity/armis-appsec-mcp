"""Tests for security_db.py — database integrity and lookup logic."""

import os
import sys

_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from security_db import SECURITY_DB, SecurityFunction, lookup, lookup_all


class TestDatabaseIntegrity:
    def test_all_entries_are_security_functions(self):
        for entry in SECURITY_DB:
            assert isinstance(entry, SecurityFunction)

    def test_all_entries_have_required_fields(self):
        for entry in SECURITY_DB:
            assert entry.name, f"Entry missing name: {entry}"
            assert entry.module, f"Entry missing module: {entry}"
            assert entry.kind in ("source", "sink", "sanitizer"), f"Invalid kind: {entry}"
            assert entry.language in ("python", "javascript", "go"), f"Invalid language: {entry}"

    def test_all_cwes_are_valid_integers(self):
        for entry in SECURITY_DB:
            for cwe in entry.cwe:
                assert isinstance(cwe, int), f"Non-int CWE {cwe} in {entry}"
                assert cwe > 0, f"Invalid CWE {cwe} in {entry}"

    def test_no_exact_duplicates(self):
        seen = set()
        for entry in SECURITY_DB:
            key = (entry.name, entry.module, entry.language)
            assert key not in seen, f"Duplicate entry: {key}"
            seen.add(key)

    def test_minimum_entry_count(self):
        assert len(SECURITY_DB) >= 100

    def test_covers_all_languages(self):
        languages = {e.language for e in SECURITY_DB}
        assert "python" in languages
        assert "javascript" in languages
        assert "go" in languages

    def test_covers_all_kinds(self):
        kinds = {e.kind for e in SECURITY_DB}
        assert "source" in kinds
        assert "sink" in kinds
        assert "sanitizer" in kinds


class TestLookup:
    def test_finds_known_sink(self):
        result = lookup("execute", language="python")
        assert result is not None
        assert result.kind == "sink"

    def test_finds_known_source(self):
        result = lookup("Getenv", language="go")
        assert result is not None
        assert result.kind == "source"

    def test_returns_none_for_unknown(self):
        result = lookup("my_custom_function")
        assert result is None

    def test_language_filter(self):
        result = lookup("run", language="python")
        assert result is not None
        assert result.language == "python"

    def test_lookup_all_returns_list(self):
        results = lookup_all("execute")
        assert len(results) >= 2  # sqlite3 + psycopg2 + ...

    def test_lookup_all_empty_for_unknown(self):
        results = lookup_all("definitely_not_a_function")
        assert results == []
