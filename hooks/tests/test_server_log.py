"""Tests for server_log.py and the server's tool-call logging / debug_config lines."""

import asyncio
import logging
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import server
import server_log


@pytest.fixture
def clean_root_logger():
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    yield root
    for h in root.handlers[:]:
        if h not in saved_handlers:
            h.close()
            root.removeHandler(h)
    root.setLevel(saved_level)


class TestRedact:
    def test_proxy_userinfo(self):
        assert (
            server_log.redact("via http://alice:pw@proxy:8080 ok") == "via http://***@proxy:8080 ok"
        )

    def test_bearer_token(self):
        out = server_log.redact("Authorization: Bearer eyJhbGciOi.eyJzdWIi.sig-_x")
        assert out == "Authorization: Bearer ***"

    def test_token_fields(self):
        out = server_log.redact('{"access_token": "abc123", "refresh_token":"def456"}')
        assert "abc123" not in out
        assert "def456" not in out

    def test_client_secret_assignment(self):
        assert "hunter2" not in server_log.redact("client_secret=hunter2&grant_type=x")

    def test_plain_text_unchanged(self):
        assert server_log.redact("tool scan_diff ok in 1.20s") == "tool scan_diff ok in 1.20s"


class TestSetupLogging:
    def test_creates_log_file_under_plugin_dir(self, tmp_path, clean_root_logger):
        path = server_log.setup_logging(str(tmp_path))
        assert path == os.path.join(str(tmp_path), "logs", "server.log")
        logging.getLogger("appsec-mcp").info("hello via http://u:secretpw@proxy:1")
        for h in clean_root_logger.handlers:
            h.flush()
        text = open(path, encoding="utf-8").read()
        assert "hello via http://***@proxy:1" in text
        assert "secretpw" not in text

    def test_uses_rotating_handler(self, tmp_path, clean_root_logger):
        server_log.setup_logging(str(tmp_path))
        rotating = [
            h
            for h in clean_root_logger.handlers
            if isinstance(h, logging.handlers.RotatingFileHandler)
        ]
        assert rotating
        assert rotating[-1].maxBytes == server_log.LOG_MAX_BYTES
        assert rotating[-1].backupCount == server_log.LOG_BACKUP_COUNT

    def test_never_writes_to_stdout(self, tmp_path, clean_root_logger):
        server_log.setup_logging(str(tmp_path))
        for h in clean_root_logger.handlers:
            if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
                assert h.stream is not sys.stdout

    def test_unwritable_dir_continues_without_file(self, tmp_path, clean_root_logger):
        blocker = tmp_path / "logs"
        blocker.write_text("a file where the log dir should be")
        before = set(clean_root_logger.handlers)
        assert server_log.setup_logging(str(tmp_path)) is None
        added = [h for h in clean_root_logger.handlers if h not in before]
        assert not any(isinstance(h, logging.FileHandler) for h in added)

    def test_exception_hook_logs_traceback(self, tmp_path, clean_root_logger, monkeypatch):
        monkeypatch.setattr(sys, "excepthook", sys.excepthook)
        monkeypatch.setattr(server_log.threading, "excepthook", server_log.threading.excepthook)
        path = server_log.setup_logging(str(tmp_path))
        server_log.install_exception_hooks()
        try:
            raise ValueError("kaboom")
        except ValueError:
            sys.excepthook(*sys.exc_info())
        for h in clean_root_logger.handlers:
            h.flush()
        text = open(path, encoding="utf-8").read()
        assert "Unhandled exception" in text
        assert "Traceback" in text
        assert "ValueError: kaboom" in text


class TestLoggedTool:
    def test_success_logged(self, caplog):
        @server._logged_tool
        async def my_tool(x: int) -> int:
            return x + 1

        with caplog.at_level(logging.INFO, logger="appsec-mcp"):
            assert asyncio.run(my_tool(1)) == 2
        assert "tool my_tool ok in" in caplog.text

    def test_tool_error_logged_and_reraised(self, caplog):
        @server._logged_tool
        async def my_tool() -> str:
            # server.ToolError: test_mcp_integration may swap in a fake ToolError
            # class before server is first imported.
            raise server.ToolError("API down")

        with caplog.at_level(logging.INFO, logger="appsec-mcp"), pytest.raises(server.ToolError):
            asyncio.run(my_tool())
        assert "tool my_tool failed in" in caplog.text
        assert "API down" in caplog.text

    def test_crash_logged_with_traceback(self, caplog):
        @server._logged_tool
        async def my_tool() -> str:
            raise KeyError("boom")

        with caplog.at_level(logging.INFO, logger="appsec-mcp"), pytest.raises(KeyError):
            asyncio.run(my_tool())
        record = next(r for r in caplog.records if "crashed" in r.getMessage())
        assert record.exc_info is not None

    def test_preserves_signature_for_fastmcp(self):
        import inspect

        params = inspect.signature(server.scan_diff).parameters
        assert "repo_path" in params
        assert "ctx" in params


class TestDebugConfigNetworkLines:
    def test_lines_present(self, monkeypatch):
        monkeypatch.setitem(server._runtime, "ca_source", "truststore")
        monkeypatch.setitem(server._runtime, "proxy", "system http://***@proxy:8080")
        monkeypatch.setitem(server._runtime, "log_file", "/x/logs/server.log")
        with patch("server.get_auth_status", return_value="not initialized"):
            result = server.get_debug_config()
        assert "CA source: truststore" in result
        assert "Proxy: system http://***@proxy:8080" in result
        assert "Log file: /x/logs/server.log" in result

    def test_defaults_before_startup(self):
        with patch("server.get_auth_status", return_value="not initialized"):
            result = server.get_debug_config()
        assert "CA source: " in result
        assert "Proxy: " in result
        assert "Log file: " in result
