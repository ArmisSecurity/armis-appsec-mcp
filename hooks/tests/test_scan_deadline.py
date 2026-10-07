"""Tests for the scan deadline, stage tracking, scan_files, and credential report."""

import asyncio
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import scanner_core
import server

_EMPTY = "```json\n[]\n```"


class TestScanDeadline:
    def test_default_and_override(self, monkeypatch):
        monkeypatch.delenv("APPSEC_SCAN_TIMEOUT", raising=False)
        assert server._scan_deadline() == 180.0
        monkeypatch.setenv("APPSEC_SCAN_TIMEOUT", "45")
        assert server._scan_deadline() == 45.0
        monkeypatch.setenv("APPSEC_SCAN_TIMEOUT", "junk")
        assert server._scan_deadline() == 180.0
        monkeypatch.setenv("APPSEC_SCAN_TIMEOUT", "-5")
        assert server._scan_deadline() == 180.0

    def test_timeout_names_the_stage(self, monkeypatch):
        monkeypatch.setenv("APPSEC_SCAN_TIMEOUT", "0.3")

        def hang(code):
            scanner_core._enter_stage("waiting for the scan API to respond (3 chars)")
            time.sleep(1.0)
            return _EMPTY

        with patch.object(server, "call_appsec_api", hang):
            with pytest.raises(RuntimeError, match="timed out after 0s while waiting for the scan"):
                asyncio.run(server._call_api("abc", None))

    def test_worker_timeout_error_is_not_reported_as_deadline(self, monkeypatch):
        monkeypatch.setenv("APPSEC_SCAN_TIMEOUT", "30")

        def boom(code):
            raise TimeoutError("socket timed out")

        with patch.object(server, "call_appsec_api", boom):
            with pytest.raises(TimeoutError, match="socket timed out"):
                asyncio.run(server._call_api("abc", None))

    def test_timeout_includes_pending_signin(self, monkeypatch):
        monkeypatch.setenv("APPSEC_SCAN_TIMEOUT", "0.2")

        def hang(code):
            time.sleep(0.6)
            return _EMPTY

        with (
            patch.object(server, "call_appsec_api", hang),
            patch.object(server, "get_pending_signin", return_value="open https://x code AB-12."),
        ):
            with pytest.raises(RuntimeError, match=r"open https://x code AB-12\. Then retry"):
                asyncio.run(server._call_api("abc", None))

    def test_success_returns_raw(self):
        with patch.object(server, "call_appsec_api", lambda code: _EMPTY):
            assert asyncio.run(server._call_api("abc", None)) == _EMPTY

    def test_stage_is_visible_inside_worker_thread(self):
        seen = {}

        def fake(code):
            scanner_core._enter_stage("custom step")
            seen["stage"] = scanner_core.current_stage.get().name
            return _EMPTY

        with patch.object(server, "call_appsec_api", fake):
            asyncio.run(server._call_api("abc", None))
        assert seen["stage"] == "custom step"
        assert scanner_core.current_stage.get() is None


class TestHeartbeat:
    def test_reports_progress_and_pending_signin_once(self, monkeypatch):
        monkeypatch.setattr(server, "_HEARTBEAT_SECONDS", 0.05)
        ctx = MagicMock()
        calls = {"info": [], "progress": 0}

        async def info(msg):
            calls["info"].append(msg)

        async def progress(*a, **k):
            calls["progress"] += 1

        ctx.info, ctx.report_progress = info, progress

        async def run():
            task = asyncio.create_task(server._heartbeat(ctx, scanner_core.ScanStage(), 10.0))
            await asyncio.sleep(0.3)
            task.cancel()

        with patch.object(server, "get_pending_signin", return_value="sign in at U"):
            asyncio.run(run())
        assert calls["info"] == ["sign in at U"]
        assert calls["progress"] >= 2

    def test_failure_does_not_stop_heartbeat(self, monkeypatch):
        monkeypatch.setattr(server, "_HEARTBEAT_SECONDS", 0.05)
        ctx = MagicMock()
        n = {"c": 0}

        async def boom(*a, **k):
            n["c"] += 1
            raise RuntimeError("client gone")

        ctx.report_progress = boom

        async def run():
            task = asyncio.create_task(server._heartbeat(ctx, scanner_core.ScanStage(), 10.0))
            await asyncio.sleep(0.3)
            task.cancel()

        asyncio.run(run())
        assert n["c"] >= 2


class TestCallApiStages:
    def test_logs_stages_and_sets_stage(self, caplog):
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"raw_response": _EMPTY}
        stage = scanner_core.ScanStage()
        token = scanner_core.current_stage.set(stage)
        try:
            with (
                caplog.at_level("INFO", logger="appsec-mcp"),
                patch("scanner_core.get_auth_header", return_value="Bearer t"),
                patch("scanner_core.httpx.post", return_value=resp),
            ):
                scanner_core.call_appsec_api("abc")
        finally:
            scanner_core.current_stage.reset(token)
        text = caplog.text
        assert "Auth token ready" in text
        assert "POST " in text and "Scan API responded HTTP 200" in text
        assert "scan API" in stage.name


class TestCredentialReport:
    def test_reports_sources_without_values(self, monkeypatch, tmp_path):
        env = tmp_path / ".env"
        env.write_text("ARMIS_CLIENT_ID=from-file\n")
        monkeypatch.setattr(server, "_env_file", str(env))
        monkeypatch.setenv("ARMIS_CLIENT_ID", "from-file")
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "shell-secret-value")
        monkeypatch.delenv("ARMIS_TENANT_ID", raising=False)
        text = "\n".join(server._credential_report())
        assert "client id set (.env)" in text
        assert "client secret set (process env)" in text
        assert "tenant id not set" in text
        assert "shell-secret-value" not in text and "from-file" not in text

    def test_hint_when_no_credentials(self, monkeypatch, tmp_path):
        monkeypatch.setattr(server, "_env_file", str(tmp_path / ".env"))
        for name in (
            "ARMIS_CLIENT_ID",
            "ARMIS_CLIENT_SECRET",
            "ARMIS_TENANT_ID",
            "ARMIS_DEFAULT_AUTH_METHOD",
        ):
            monkeypatch.delenv(name, raising=False)
        text = "\n".join(server._credential_report())
        assert "missing" in text
        assert "not inherited by editor-launched servers" in text

    def test_sso_note_when_credentials_are_ignored(self, monkeypatch, tmp_path):
        monkeypatch.setattr(server, "_env_file", str(tmp_path / ".env"))
        monkeypatch.setenv("ARMIS_CLIENT_ID", "id")
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "secret")
        monkeypatch.setenv("ARMIS_DEFAULT_AUTH_METHOD", "SSO")
        text = "\n".join(server._credential_report())
        assert "client credentials are ignored" in text
