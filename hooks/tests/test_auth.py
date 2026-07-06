"""Tests for auth.py — JWT authentication provider."""

import base64
import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

# Add plugin dir to path so we can import auth
_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from datetime import UTC

import auth
from auth import JWTAuth, SharedCacheAuth, get_auth_header, get_auth_status, init_auth
from device_auth import DeviceAuthorization, OAuthError
from token_cache import StoredToken, TokenStore


def _future(seconds: int = 3600):
    from datetime import datetime, timedelta

    return datetime.now(UTC) + timedelta(seconds=seconds)


def _make_jwt(exp: float = None, extra_claims: dict = None) -> str:
    """Build a fake JWT with the given exp claim (no real signature)."""
    if exp is None:
        exp = time.time() + 3600  # 1 hour from now
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=")
    claims = {"exp": exp, "sub": "test"}
    if extra_claims:
        claims.update(extra_claims)
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
    signature = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}.{signature.decode()}"


# ---------------------------------------------------------------------------
# init_auth
# ---------------------------------------------------------------------------
class TestInitAuth:
    def setup_method(self):
        """Reset module singleton before each test."""
        auth._auth = None

    def test_success_with_both_credentials(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_ID", "test-id")
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "test-secret")
        init_auth("https://example.com/api/v1")
        assert auth._auth is not None

    def test_no_creds_builds_shared_cache_auth(self, monkeypatch):
        # PPSC-1038: with no client credentials, init_auth now falls back to the
        # shared token cache / Device Auth provider (lazy — no disk/network here).
        monkeypatch.delenv("ARMIS_CLIENT_ID", raising=False)
        monkeypatch.delenv("ARMIS_CLIENT_SECRET", raising=False)
        init_auth("https://example.com/api/v1")
        assert isinstance(auth._auth, auth.SharedCacheAuth)
        assert auth.get_auth_method() == "shared-cache/SSO"

    def test_both_creds_uses_jwt_auth(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_ID", "test-id")
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "test-secret")
        init_auth("https://example.com/api/v1")
        assert isinstance(auth._auth, JWTAuth)
        assert auth.get_auth_method() == "client-credentials"

    def test_error_when_only_client_id(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_ID", "test-id")
        monkeypatch.delenv("ARMIS_CLIENT_SECRET", raising=False)
        with pytest.raises(RuntimeError, match="ARMIS_CLIENT_SECRET is not set"):
            init_auth("https://example.com/api/v1")

    def test_error_when_only_client_secret(self, monkeypatch):
        monkeypatch.delenv("ARMIS_CLIENT_ID", raising=False)
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "test-secret")
        with pytest.raises(RuntimeError, match="ARMIS_CLIENT_ID is not set"):
            init_auth("https://example.com/api/v1")


# ---------------------------------------------------------------------------
# JWTAuth.exchange
# ---------------------------------------------------------------------------
class TestJWTAuthExchange:
    @pytest.fixture(autouse=True)
    def _set_secret(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "secret")

    def test_success(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        fake_token = _make_jwt(exp=time.time() + 3600)
        mock_response = MagicMock()
        mock_response.json.return_value = {"token": fake_token, "region": "us1"}
        mock_response.raise_for_status = MagicMock()

        with patch("auth.httpx.post", return_value=mock_response) as mock_post:
            jwt_auth.exchange()

        assert jwt_auth._token == fake_token
        assert jwt_auth._expires_at > time.time()
        mock_post.assert_called_once()

    def test_401_raises_clear_error(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        mock_response = MagicMock()
        mock_response.status_code = 401
        error = __import__("httpx").HTTPStatusError(
            "Unauthorized", request=MagicMock(), response=mock_response
        )
        mock_response.raise_for_status.side_effect = error

        with patch("auth.httpx.post", return_value=mock_response):
            with pytest.raises(RuntimeError, match="invalid client_id/client_secret"):
                jwt_auth.exchange()

    def test_timeout_raises_clear_error(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        with patch(
            "auth.httpx.post",
            side_effect=__import__("httpx").TimeoutException("timed out"),
        ):
            with pytest.raises(RuntimeError, match="connection timeout"):
                jwt_auth.exchange()

    def test_missing_token_key_raises(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        mock_response = MagicMock()
        mock_response.json.return_value = {"region": "us1"}  # no "token" key
        mock_response.raise_for_status = MagicMock()

        with patch("auth.httpx.post", return_value=mock_response):
            with pytest.raises(RuntimeError, match="missing token"):
                jwt_auth.exchange()

    def test_https_enforcement_rejects_http(self):
        jwt_auth = JWTAuth("http://evil.com/api/v1", "id")
        with pytest.raises(RuntimeError, match="HTTPS"):
            jwt_auth.exchange()

    def test_https_allows_localhost(self):
        jwt_auth = JWTAuth("http://localhost:8001/api/v1", "id")
        fake_token = _make_jwt()
        mock_response = MagicMock()
        mock_response.json.return_value = {"token": fake_token, "region": "us1"}
        mock_response.raise_for_status = MagicMock()

        with patch("auth.httpx.post", return_value=mock_response):
            jwt_auth.exchange()
        assert jwt_auth._token == fake_token

    def test_missing_env_secret_raises(self, monkeypatch):
        monkeypatch.delenv("ARMIS_CLIENT_SECRET", raising=False)
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        with pytest.raises(RuntimeError, match="ARMIS_CLIENT_SECRET is not set"):
            jwt_auth.exchange()


# ---------------------------------------------------------------------------
# JWTAuth.get_header
# ---------------------------------------------------------------------------
class TestJWTAuthGetHeader:
    @pytest.fixture(autouse=True)
    def _set_secret(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "secret")

    def test_first_call_triggers_exchange(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        fake_token = _make_jwt(exp=time.time() + 3600)
        mock_response = MagicMock()
        mock_response.json.return_value = {"token": fake_token, "region": "us1"}
        mock_response.raise_for_status = MagicMock()

        with patch("auth.httpx.post", return_value=mock_response) as mock_post:
            header = jwt_auth.get_header()

        assert header == f"Bearer {fake_token}"
        mock_post.assert_called_once()

    def test_cached_token_no_second_exchange(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        fake_token = _make_jwt(exp=time.time() + 3600)
        jwt_auth._token = fake_token
        jwt_auth._expires_at = time.time() + 3600

        with patch("auth.httpx.post") as mock_post:
            header = jwt_auth.get_header()

        assert header == f"Bearer {fake_token}"
        mock_post.assert_not_called()

    def test_expired_token_triggers_reexchange(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        jwt_auth._token = "old-token"
        jwt_auth._expires_at = time.time() - 100  # already expired

        new_token = _make_jwt(exp=time.time() + 3600)
        mock_response = MagicMock()
        mock_response.json.return_value = {"token": new_token, "region": "us1"}
        mock_response.raise_for_status = MagicMock()

        with patch("auth.httpx.post", return_value=mock_response) as mock_post:
            header = jwt_auth.get_header()

        assert header == f"Bearer {new_token}"
        mock_post.assert_called_once()


# ---------------------------------------------------------------------------
# JWTAuth._parse_jwt_exp
# ---------------------------------------------------------------------------
class TestParseJWTExp:
    def test_valid_jwt(self):
        exp = time.time() + 7200
        token = _make_jwt(exp=exp)
        result = JWTAuth._parse_jwt_exp(token)
        assert abs(result - exp) < 1  # floating point tolerance

    def test_malformed_jwt_not_3_parts(self):
        with pytest.raises(ValueError, match="3 dot-separated"):
            JWTAuth._parse_jwt_exp("only.two")

    def test_invalid_base64(self):
        with pytest.raises(Exception):
            JWTAuth._parse_jwt_exp("header.!!!invalid!!!.sig")

    def test_missing_exp_claim(self):
        header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=")
        payload = base64.urlsafe_b64encode(b'{"sub":"test"}').rstrip(b"=")
        sig = base64.urlsafe_b64encode(b"sig").rstrip(b"=")
        token = f"{header.decode()}.{payload.decode()}.{sig.decode()}"
        with pytest.raises(KeyError):
            JWTAuth._parse_jwt_exp(token)

    def test_exp_in_past_raises(self):
        token = _make_jwt(exp=time.time() - 100)
        with pytest.raises(ValueError, match="in the past"):
            JWTAuth._parse_jwt_exp(token)

    def test_exp_too_far_future_raises(self):
        token = _make_jwt(exp=time.time() + 100_000)
        with pytest.raises(ValueError, match="more than 24h"):
            JWTAuth._parse_jwt_exp(token)


# ---------------------------------------------------------------------------
# Module-level functions
# ---------------------------------------------------------------------------
class TestModuleFunctions:
    def setup_method(self):
        auth._auth = None

    def test_get_auth_header_before_init_raises(self):
        with pytest.raises(RuntimeError, match="not initialized"):
            get_auth_header()

    def test_get_auth_status_before_init(self):
        assert get_auth_status() == "not initialized"

    def test_get_auth_status_after_init(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_ID", "test-id")
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "test-secret")
        init_auth("https://example.com/api/v1")
        assert get_auth_status() == "not yet exchanged"


# ---------------------------------------------------------------------------
# JWTAuth.status()
# ---------------------------------------------------------------------------
class TestJWTAuthStatus:
    def test_status_not_yet_exchanged(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        assert jwt_auth.status() == "not yet exchanged"

    def test_status_expired(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        jwt_auth._token = "old-token"
        jwt_auth._expires_at = time.time() - 100
        assert jwt_auth.status() == "expired"

    def test_status_valid_with_remaining_time(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        jwt_auth._token = _make_jwt(exp=time.time() + 1800)
        jwt_auth._expires_at = time.time() + 1800  # 30 minutes
        status = jwt_auth.status()
        assert "valid" in status
        assert "30m" in status or "29m" in status


# ---------------------------------------------------------------------------
# JWTAuth.exchange — non-JSON response
# ---------------------------------------------------------------------------
class TestExchangeNonJsonResponse:
    @pytest.fixture(autouse=True)
    def _set_secret(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "secret")

    def test_non_json_200_raises_clear_error(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.side_effect = __import__("json").JSONDecodeError(
            "Expecting value", "<html>", 0
        )

        with patch("auth.httpx.post", return_value=mock_response):
            with pytest.raises(RuntimeError, match="invalid response"):
                jwt_auth.exchange()


# ---------------------------------------------------------------------------
# SharedCacheAuth (PPSC-1038): shared token cache + Device Auth fallback
# ---------------------------------------------------------------------------
class TestSharedCacheAuth:
    ISSUER = "https://moose.armis.com"

    def _make(self, tmp_path):
        """Build a SharedCacheAuth backed by an isolated store (never real ~/.armis)."""
        store = TokenStore(dir=str(tmp_path))
        return SharedCacheAuth(self.ISSUER, store=store), store

    def test_valid_cached_token_used_without_network(self, tmp_path):
        provider, store = self._make(tmp_path)
        store.save(self.ISSUER, StoredToken(access_token="cached", expires_at=_future()))

        with patch("device_auth.httpx.post") as mock_post:
            header = provider.get_header()

        assert header == "Bearer cached"
        mock_post.assert_not_called()

    def test_in_memory_token_reused(self, tmp_path):
        provider, store = self._make(tmp_path)
        store.save(self.ISSUER, StoredToken(access_token="cached", expires_at=_future()))
        provider.get_header()  # loads into memory
        # Remove from disk; the in-memory copy should still serve.
        store.save(self.ISSUER, StoredToken(access_token="", refresh_token=""))
        assert provider.get_header() == "Bearer cached"

    def test_expired_token_with_refresh_refreshes_and_persists(self, tmp_path):
        provider, store = self._make(tmp_path)
        store.save(
            self.ISSUER,
            StoredToken(
                access_token="old",
                refresh_token="r1",
                expires_at=_future(-100),  # expired
                tenant_id="t",
                client_id="armis-cli",
            ),
        )
        rotated = StoredToken(access_token="new", refresh_token="r2", expires_at=_future())

        with patch.object(provider._device, "refresh", return_value=rotated) as mock_refresh:
            header = provider.get_header()

        assert header == "Bearer new"
        mock_refresh.assert_called_once_with("r1", "armis-cli")
        # Rotated pair persisted to the shared cache.
        persisted = store.load(self.ISSUER)
        assert persisted.refresh_token == "r2"
        # Identity carried forward when the refresh response omitted it.
        assert persisted.tenant_id == "t"

    def test_refresh_invalid_grant_falls_back_to_device_login(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ARMIS_TENANT_ID", "tenant1")
        provider, store = self._make(tmp_path)
        store.save(
            self.ISSUER,
            StoredToken(access_token="old", refresh_token="r1", expires_at=_future(-100)),
        )
        da = DeviceAuthorization("dc", "UC", "https://v", "https://v?c=UC", 600, 5)
        fresh = StoredToken(access_token="fresh", refresh_token="rn", expires_at=_future())

        with (
            patch.object(provider._device, "refresh", side_effect=OAuthError("invalid_grant")),
            patch.object(provider._device, "request_device_code", return_value=da),
            patch.object(provider._device, "poll_token", return_value=fresh),
            patch("shared_cache_auth.open_browser", return_value=False),
        ):
            header = provider.get_header()

        assert header == "Bearer fresh"
        assert store.load(self.ISSUER).access_token == "fresh"

    def test_empty_cache_without_tenant_raises(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ARMIS_TENANT_ID", raising=False)
        provider, _ = self._make(tmp_path)
        with pytest.raises(RuntimeError, match="ARMIS_TENANT_ID"):
            provider.get_header()

    def test_empty_cache_with_tenant_runs_device_flow(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ARMIS_TENANT_ID", "tenant1")
        provider, store = self._make(tmp_path)
        da = DeviceAuthorization("dc", "UC", "https://v", "https://v?c=UC", 600, 5)
        fresh = StoredToken(access_token="fresh", refresh_token="rn", expires_at=_future())

        with (
            patch.object(provider._device, "request_device_code", return_value=da) as mock_req,
            patch.object(provider._device, "poll_token", return_value=fresh) as mock_poll,
            patch("shared_cache_auth.open_browser", return_value=True),
        ):
            header = provider.get_header()

        assert header == "Bearer fresh"
        mock_req.assert_called_once()
        mock_poll.assert_called_once()
        assert store.load(self.ISSUER).access_token == "fresh"

    def test_device_flow_uses_public_client_id(self, tmp_path, monkeypatch):
        # The device flow is a public client (no secret); it identifies with the
        # hardcoded public client_id armis-cli defaults to, not a per-install env var.
        from device_auth import DEFAULT_DEVICE_CLIENT_ID

        monkeypatch.setenv("ARMIS_TENANT_ID", "tenant1")
        provider, _ = self._make(tmp_path)
        da = DeviceAuthorization("dc", "UC", "https://v", "https://v?c=UC", 600, 5)
        fresh = StoredToken(access_token="fresh", expires_at=_future())

        with (
            patch.object(provider._device, "request_device_code", return_value=da) as mock_req,
            patch.object(provider._device, "poll_token", return_value=fresh),
            patch("shared_cache_auth.open_browser", return_value=False),
        ):
            provider.get_header()

        assert mock_req.call_args.args[0] == DEFAULT_DEVICE_CLIENT_ID

    def test_status_labels_are_token_free(self, tmp_path):
        provider, store = self._make(tmp_path)
        assert provider.status() == "shared cache: not signed in"

        store.save(
            self.ISSUER, StoredToken(access_token="a-secret-token", expires_at=_future(1800))
        )
        provider._token = None  # force reload from disk
        status = provider.status()
        assert "valid" in status
        assert "a-secret-token" not in status
