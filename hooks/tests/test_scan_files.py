"""Tests for scan_files."""

import asyncio
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import server

_EMPTY = "```json\n[]\n```"


class TestScanFiles:
    def _run(self, paths):
        return asyncio.run(server.scan_files(paths))

    def test_rejects_empty_and_too_many(self):
        with pytest.raises(server.ToolError, match="at least one"):
            self._run([])
        with pytest.raises(server.ToolError, match="Too many"):
            self._run([f"/tmp/f{i}.py" for i in range(server._MAX_SCAN_FILES + 1)])

    def test_one_failure_does_not_stop_the_rest(self, tmp_path):
        good = tmp_path / "a.py"
        good.write_text("x = 1\n")
        missing = tmp_path / "nope.py"
        with patch.object(server, "call_appsec_api", lambda code: _EMPTY):
            out = self._run([str(missing), str(good)])
        assert "nope.py: ERROR" in out
        assert "a.py" in out
        assert out.count("\n\n") >= 1

    def test_timeout_skips_remaining_files(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APPSEC_SCAN_TIMEOUT", "0.2")
        files = []
        for name in ("a.py", "b.py", "c.py"):
            f = tmp_path / name
            f.write_text("x = 1\n")
            files.append(str(f))
        calls = []

        def hang(code):
            calls.append(1)
            import time

            time.sleep(0.6)
            return _EMPTY

        with patch.object(server, "call_appsec_api", hang):
            out = self._run(files)
        assert len(calls) == 1
        assert "a.py: ERROR" in out and "timed out" in out
        assert "b.py: SKIPPED" in out and "c.py: SKIPPED" in out
