"""Tests for device_auth.py — the RFC 8628 device-flow client."""

import base64
import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from device_auth import DeviceClient, OAuthError, open_browser


def _make_jwt(claims: dict) -> str:
    """Build a fake JWT (no real signature) carrying the given claims."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
    sig = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}.{sig.decode()}"


def _resp(status: int, body) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = body if isinstance(body, str) else json.dumps(body)
    return r


# ---------------------------------------------------------------------------
# Construction / HTTPS enforcement
# ---------------------------------------------------------------------------
class TestDeviceClientInit:
    def test_https_required_for_non_localhost(self):
        with pytest.raises(RuntimeError, match="HTTPS"):
            DeviceClient("http://moose.armis.com")

    def test_localhost_http_allowed(self):
        assert DeviceClient("http://localhost:8001") is not None

    def test_empty_issuer_rejected(self):
        with pytest.raises(ValueError, match="issuer"):
            DeviceClient("")


# ---------------------------------------------------------------------------
# request_device_code
# ---------------------------------------------------------------------------
class TestRequestDeviceCode:
    def test_success(self):
        client = DeviceClient("https://moose.armis.com")
        body = {
            "device_code": "dev123",
            "user_code": "WXYZ-1234",
            "verification_uri": "https://moose.armis.com/oauth2/device/verify",
            "verification_uri_complete": "https://moose.armis.com/oauth2/device/verify?code=WXYZ",
            "expires_in": 600,
            "interval": 5,
        }
        with patch("device_auth.httpx.post", return_value=_resp(200, body)):
            da = client.request_device_code("armis-cli", "tenant1")
        assert da.device_code == "dev123"
        assert da.user_code == "WXYZ-1234"
        assert da.interval == 5

    def test_missing_tenant_raises(self):
        client = DeviceClient("https://moose.armis.com")
        with pytest.raises(ValueError, match="tenant_id is required"):
            client.request_device_code("armis-cli", "")

    def test_error_status_raises_oauth_error(self):
        client = DeviceClient("https://moose.armis.com")
        with patch(
            "device_auth.httpx.post",
            return_value=_resp(400, {"error": "invalid_request", "error_description": "bad"}),
        ):
            with pytest.raises(OAuthError) as ei:
                client.request_device_code("armis-cli", "tenant1")
        assert ei.value.code == "invalid_request"

    def test_missing_fields_raises(self):
        client = DeviceClient("https://moose.armis.com")
        with patch("device_auth.httpx.post", return_value=_resp(200, {"device_code": "x"})):
            with pytest.raises(RuntimeError, match="missing required fields"):
                client.request_device_code("armis-cli", "tenant1")


# ---------------------------------------------------------------------------
# poll_token
# ---------------------------------------------------------------------------
class TestPollToken:
    def _token_body(self):
        access = _make_jwt(
            {
                "exp": time.time() + 3600,
                "tenant_id": "tenant1",
                "sub": "user@corp",
                "role": "developer",
                "iss": "https://moose.armis.com",
                "region": "us1",
            }
        )
        return {"access_token": access, "refresh_token": "refresh1", "expires_in": 3600}

    def test_pending_then_slow_down_then_success(self):
        client = DeviceClient("https://moose.armis.com")
        responses = [
            _resp(400, {"error": "authorization_pending"}),
            _resp(400, {"error": "slow_down"}),
            _resp(200, self._token_body()),
        ]
        with (
            patch("device_auth.httpx.post", side_effect=responses),
            patch("device_auth.time.sleep") as mock_sleep,
        ):
            tok = client.poll_token(
                "dev123", "armis-cli", interval_seconds=1, expires_in_seconds=600
            )
        assert tok.access_token
        assert tok.refresh_token == "refresh1"
        assert tok.tenant_id == "tenant1"
        assert tok.subject == "user@corp"
        assert tok.region == "us1"
        # slow_down widened the interval on the second wait.
        assert mock_sleep.call_count == 3

    def test_expired_token_raises(self):
        client = DeviceClient("https://moose.armis.com")
        with (
            patch("device_auth.httpx.post", return_value=_resp(400, {"error": "expired_token"})),
            patch("device_auth.time.sleep"),
        ):
            with pytest.raises(OAuthError) as ei:
                client.poll_token("dev123", "armis-cli", 1, 600)
        assert ei.value.code == "expired_token"

    def test_access_denied_raises(self):
        client = DeviceClient("https://moose.armis.com")
        with (
            patch("device_auth.httpx.post", return_value=_resp(400, {"error": "access_denied"})),
            patch("device_auth.time.sleep"),
        ):
            with pytest.raises(OAuthError) as ei:
                client.poll_token("dev123", "armis-cli", 1, 600)
        assert ei.value.code == "access_denied"

    def test_deadline_exhausted_raises_expired(self):
        client = DeviceClient("https://moose.armis.com")
        # expires_in tiny so the deadline is immediately in the past.
        with (
            patch("device_auth.time.sleep"),
            patch(
                "device_auth.httpx.post",
                return_value=_resp(400, {"error": "authorization_pending"}),
            ),
        ):
            with pytest.raises(OAuthError) as ei:
                client.poll_token("dev123", "armis-cli", interval_seconds=5, expires_in_seconds=1)
        assert ei.value.code == "expired_token"

    def test_expires_at_from_token_exp_when_no_expires_in(self):
        client = DeviceClient("https://moose.armis.com")
        access = _make_jwt({"exp": time.time() + 1800, "sub": "u"})
        body = {"access_token": access, "refresh_token": "r"}  # no expires_in
        with (
            patch("device_auth.httpx.post", return_value=_resp(200, body)),
            patch("device_auth.time.sleep"),
        ):
            tok = client.poll_token("dev123", "armis-cli", 1, 600)
        assert tok.expires_at is not None
        assert tok.seconds_remaining() > 60


# ---------------------------------------------------------------------------
# refresh
# ---------------------------------------------------------------------------
class TestRefresh:
    def test_refresh_returns_rotated_token(self):
        client = DeviceClient("https://moose.armis.com")
        access = _make_jwt({"exp": time.time() + 3600, "sub": "u", "tenant_id": "t"})
        body = {"access_token": access, "refresh_token": "rotated", "expires_in": 3600}
        with patch("device_auth.httpx.post", return_value=_resp(200, body)):
            tok = client.refresh("old-refresh", "armis-cli")
        assert tok.refresh_token == "rotated"
        assert tok.client_id == "armis-cli"

    def test_refresh_invalid_grant_raises_oauth_error(self):
        client = DeviceClient("https://moose.armis.com")
        with patch("device_auth.httpx.post", return_value=_resp(400, {"error": "invalid_grant"})):
            with pytest.raises(OAuthError) as ei:
                client.refresh("old-refresh", "armis-cli")
        assert ei.value.code == "invalid_grant"

    def test_missing_access_token_raises(self):
        client = DeviceClient("https://moose.armis.com")
        with patch("device_auth.httpx.post", return_value=_resp(200, {"refresh_token": "r"})):
            with pytest.raises(RuntimeError, match="missing access_token"):
                client.refresh("old-refresh", "armis-cli")


# ---------------------------------------------------------------------------
# open_browser
# ---------------------------------------------------------------------------
class TestOpenBrowser:
    def test_rejects_non_http_scheme(self):
        assert open_browser("file:///etc/passwd") is False
        assert open_browser("javascript:alert(1)") is False

    def test_opens_https(self):
        with patch("device_auth.webbrowser.open", return_value=True) as mock_open:
            assert open_browser("https://moose.armis.com/verify") is True
        mock_open.assert_called_once()

    def test_never_raises_on_webbrowser_error(self):
        with patch("device_auth.webbrowser.open", side_effect=RuntimeError("no display")):
            assert open_browser("https://moose.armis.com/verify") is False
