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

    @pytest.fixture(autouse=True)
    def _no_sso_by_default(self, monkeypatch):
        # Most cases assume the SSO opt-in is NOT set; SSO-specific tests set it.
        monkeypatch.delenv("ARMIS_DEFAULT_AUTH_METHOD", raising=False)

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

    def test_sso_opt_in_forces_shared_cache(self, monkeypatch):
        # ARMIS_DEFAULT_AUTH_METHOD=sso selects the shared-cache / Device Auth path.
        monkeypatch.setenv("ARMIS_DEFAULT_AUTH_METHOD", "sso")
        monkeypatch.delenv("ARMIS_CLIENT_ID", raising=False)
        monkeypatch.delenv("ARMIS_CLIENT_SECRET", raising=False)
        init_auth("https://example.com/api/v1")
        assert isinstance(auth._auth, auth.SharedCacheAuth)

    def test_sso_opt_in_overrides_client_credentials(self, monkeypatch):
        # SSO opt-in wins even when client credentials are present.
        monkeypatch.setenv("ARMIS_DEFAULT_AUTH_METHOD", "SSO")  # case-insensitive
        monkeypatch.setenv("ARMIS_CLIENT_ID", "test-id")
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "test-secret")
        init_auth("https://example.com/api/v1")
        assert isinstance(auth._auth, auth.SharedCacheAuth)
        assert auth.get_auth_method() == "shared-cache/SSO"

    def test_sso_opt_in_ignores_partial_client_credentials(self, monkeypatch):
        # A stray ARMIS_CLIENT_ID must not raise a partial-config error under SSO.
        monkeypatch.setenv("ARMIS_DEFAULT_AUTH_METHOD", "sso")
        monkeypatch.setenv("ARMIS_CLIENT_ID", "test-id")
        monkeypatch.delenv("ARMIS_CLIENT_SECRET", raising=False)
        init_auth("https://example.com/api/v1")
        assert isinstance(auth._auth, auth.SharedCacheAuth)


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

    def test_invalidate_forces_reexchange(self):
        # After a 401, invalidate() drops the cached token so the next call
        # re-exchanges credentials even though the old token hadn't expired.
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        jwt_auth._token = "killed-token"
        jwt_auth._expires_at = time.time() + 3600  # still valid locally

        jwt_auth.invalidate()
        assert jwt_auth._token is None

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

    @pytest.fixture(autouse=True)
    def _no_sso_by_default(self, monkeypatch):
        # Hermetic: a shell-exported ARMIS_DEFAULT_AUTH_METHOD=sso must not steer
        # the client-credentials path this class exercises.
        monkeypatch.delenv("ARMIS_DEFAULT_AUTH_METHOD", raising=False)

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

    def test_invalidate_rejects_killed_token_and_reauths(self, tmp_path, monkeypatch):
        # A locally-valid token that the server killed (401): after invalidate(),
        # the same cached token must NOT be reused — re-auth (refresh) instead.
        provider, store = self._make(tmp_path)
        store.save(
            self.ISSUER,
            StoredToken(
                access_token="killed",
                refresh_token="r1",
                expires_at=_future(1800),  # still valid locally
                client_id="armis-cli",
            ),
        )
        assert provider.get_header() == "Bearer killed"

        provider.invalidate()  # scan came back 401

        rotated = StoredToken(access_token="new", refresh_token="r2", expires_at=_future())
        with patch.object(provider._device, "refresh", return_value=rotated) as mock_refresh:
            header = provider.get_header()

        assert header == "Bearer new"  # did NOT hand back the killed token
        mock_refresh.assert_called_once_with("r1", "armis-cli")

    def test_invalidate_skips_killed_token_even_when_reloaded_from_disk(
        self, tmp_path, monkeypatch
    ):
        # The killed token is still on disk and unexpired; invalidate() must keep
        # _ensure_access_token from re-selecting it (no infinite 401 loop).
        monkeypatch.setenv("ARMIS_TENANT_ID", "tenant1")
        provider, store = self._make(tmp_path)
        store.save(
            self.ISSUER,
            StoredToken(access_token="killed", expires_at=_future(1800)),  # no refresh token
        )
        assert provider.get_header() == "Bearer killed"

        provider.invalidate()

        da = DeviceAuthorization("dc", "UC", "https://v", "https://v?c=UC", 600, 5)
        fresh = StoredToken(access_token="fresh", expires_at=_future())
        with (
            patch.object(provider._device, "request_device_code", return_value=da),
            patch.object(provider._device, "poll_token", return_value=fresh),
            patch("shared_cache_auth.open_browser", return_value=False),
        ):
            header = provider.get_header()

        assert header == "Bearer fresh"  # fell through to device login, not the killed token


# ---------------------------------------------------------------------------
# Concurrency: both providers are reached from several threads at once
#
# server._run_scan dispatches call_appsec_api through asyncio.to_thread, and
# the MCP SDK starts each incoming request as its own task
# (mcp/server/lowlevel/server.py: tg.start_soon(self._handle_message, ...)),
# so N in-flight tool calls mean N threads inside get_header() at once.
# Each provider must coalesce that into a single credential exchange.
# ---------------------------------------------------------------------------
class _Concurrently:
    """Run ``fn`` on ``n`` threads that all start at the same instant.

    The barrier is what makes these tests deterministic: without it a fast
    first thread could finish its exchange before the others look at the
    cache, and an unsynchronized provider would pass by luck.
    """

    def __init__(self, n: int = 8):
        self.n = n

    def __call__(self, fn):
        import threading

        barrier = threading.Barrier(self.n)
        results: list[object] = [None] * self.n
        errors: list[BaseException | None] = [None] * self.n

        def worker(i: int) -> None:
            try:
                barrier.wait(timeout=10)
                results[i] = fn()
            except BaseException as e:  # noqa: BLE001 - re-raised below
                errors[i] = e

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(self.n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
            assert not t.is_alive(), "worker thread did not finish — deadlock?"
        for e in errors:
            if e is not None:
                raise e
        return results


class TestJWTAuthConcurrency:
    @pytest.fixture(autouse=True)
    def _set_secret(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "secret")

    def test_concurrent_get_header_exchanges_once(self):
        # Every extra exchange is a wasted round trip against /auth/token, and
        # enough of them trip the endpoint's rate limiter (HTTP 429) — which the
        # scan path then reports as an auth failure.
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        fake_token = _make_jwt(exp=time.time() + 3600)

        calls = []

        def slow_post(*args, **kwargs):
            calls.append(1)
            time.sleep(0.05)  # widen the window a racing thread would exploit
            mock_response = MagicMock()
            mock_response.json.return_value = {"token": fake_token, "region": "us1"}
            mock_response.raise_for_status = MagicMock()
            return mock_response

        with patch("auth.httpx.post", side_effect=slow_post):
            headers = _Concurrently(8)(jwt_auth.get_header)

        assert len(calls) == 1, f"expected 1 token exchange, got {len(calls)}"
        assert headers == [f"Bearer {fake_token}"] * 8

    def test_concurrent_invalidate_and_get_header_never_returns_bare_bearer(self):
        # invalidate() clears _token; an unsynchronized get_header() can observe
        # that intermediate state and format "Bearer None" into a live request.
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        fake_token = _make_jwt(exp=time.time() + 3600)
        jwt_auth._token = fake_token
        jwt_auth._expires_at = time.time() + 3600

        def slow_post(*args, **kwargs):
            time.sleep(0.01)
            mock_response = MagicMock()
            mock_response.json.return_value = {"token": fake_token, "region": "us1"}
            mock_response.raise_for_status = MagicMock()
            return mock_response

        def churn():
            for _ in range(20):
                jwt_auth.invalidate()
                header = jwt_auth.get_header()
                assert header != "Bearer None", "handed out a header with no token"
                assert header.startswith("Bearer ey")
            return True

        with patch("auth.httpx.post", side_effect=slow_post):
            assert _Concurrently(4)(churn) == [True] * 4


class TestSharedCacheAuthConcurrency:
    ISSUER = "https://moose.armis.com"

    def _make(self, tmp_path):
        store = TokenStore(dir=str(tmp_path))
        return SharedCacheAuth(self.ISSUER, store=store), store

    def test_concurrent_refresh_grants_only_once(self, tmp_path):
        # The refresh grant is rotated: the first refresh invalidates "r1", so a
        # second concurrent refresh with the same token is reuse — the server's
        # reuse detection revokes the whole token family (see CLAUDE.md).
        provider, store = self._make(tmp_path)
        store.save(
            self.ISSUER,
            StoredToken(
                access_token="old",
                refresh_token="r1",
                expires_at=_future(-100),  # expired -> refresh path
                client_id="armis-cli",
            ),
        )

        calls = []

        def slow_refresh(refresh_token, client_id):
            calls.append(refresh_token)
            time.sleep(0.05)
            return StoredToken(access_token="new", refresh_token="r2", expires_at=_future())

        with patch.object(provider._device, "refresh", side_effect=slow_refresh):
            headers = _Concurrently(8)(provider.get_header)

        assert calls == ["r1"], f"refresh token replayed {len(calls)} times: {calls}"
        assert headers == ["Bearer new"] * 8

    def test_concurrent_device_login_opens_one_browser(self, tmp_path, monkeypatch):
        # Worst case of the race: N threads with an empty cache each start their
        # own RFC 8628 flow, so the developer gets N browser windows and N codes.
        monkeypatch.setenv("ARMIS_TENANT_ID", "tenant1")
        provider, store = self._make(tmp_path)
        da = DeviceAuthorization("dc", "UC", "https://v", "https://v?c=UC", 600, 5)
        fresh = StoredToken(access_token="fresh", refresh_token="rn", expires_at=_future())

        def slow_poll(*args, **kwargs):
            time.sleep(0.05)
            return fresh

        with (
            patch.object(provider._device, "request_device_code", return_value=da) as mock_req,
            patch.object(provider._device, "poll_token", side_effect=slow_poll) as mock_poll,
            patch("shared_cache_auth.open_browser", return_value=False) as mock_browser,
        ):
            headers = _Concurrently(8)(provider.get_header)

        assert mock_req.call_count == 1, f"{mock_req.call_count} device flows started"
        assert mock_poll.call_count == 1
        assert mock_browser.call_count == 1
        assert headers == ["Bearer fresh"] * 8
        assert store.load(self.ISSUER).access_token == "fresh"


class TestAuthFailureIsNotReplayed:
    """A failed exchange must be shared with the threads that waited on it.

    Coalescing the *success* path is not enough. The failure that matters is
    HTTP 429 from /auth/token, and replaying the same request N more times is
    the worst possible response to being rate limited -- measured live: 24
    concurrent scans produced 24 POSTs and 23 of them 429, and each retry
    extends the lockout window.

    Single-flight semantics: threads that arrive while an exchange is in
    flight share its outcome, success or failure. A caller arriving afterwards
    gets a fresh attempt, so a transient failure is still retryable.
    """

    @pytest.fixture(autouse=True)
    def _set_secret(self, monkeypatch):
        monkeypatch.setenv("ARMIS_CLIENT_SECRET", "secret")

    def test_concurrent_429_posts_once(self):
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        calls = []

        def rate_limited(*args, **kwargs):
            calls.append(1)
            time.sleep(0.05)
            response = MagicMock()
            response.status_code = 429
            error = __import__("httpx").HTTPStatusError(
                "429", request=MagicMock(), response=response
            )
            response.raise_for_status = MagicMock(side_effect=error)
            return response

        def attempt():
            with pytest.raises(RuntimeError, match="429"):
                jwt_auth.get_header()
            return True

        with patch("auth.httpx.post", side_effect=rate_limited):
            assert _Concurrently(8)(attempt) == [True] * 8

        assert len(calls) == 1, f"replayed a rate-limited exchange {len(calls)} times"

    def test_later_call_retries_after_a_failure(self):
        # The shared failure must not become a sticky error: a caller arriving
        # after the failed attempt gets its own exchange.
        jwt_auth = JWTAuth("https://example.com/api/v1", "id")
        fake_token = _make_jwt(exp=time.time() + 3600)

        with patch("auth.httpx.post", side_effect=RuntimeError("boom")):
            with pytest.raises(RuntimeError):
                jwt_auth.get_header()

        mock_response = MagicMock()
        mock_response.json.return_value = {"token": fake_token, "region": "us1"}
        mock_response.raise_for_status = MagicMock()
        with patch("auth.httpx.post", return_value=mock_response) as mock_post:
            assert jwt_auth.get_header() == f"Bearer {fake_token}"
        mock_post.assert_called_once()

    def test_concurrent_device_login_failure_asks_once(self, tmp_path, monkeypatch):
        # Same rule for the SSO path: one failed sign-in, not N browser prompts.
        monkeypatch.setenv("ARMIS_TENANT_ID", "tenant1")
        store = TokenStore(dir=str(tmp_path))
        provider = SharedCacheAuth("https://moose.armis.com", store=store)
        da = DeviceAuthorization("dc", "UC", "https://v", "https://v?c=UC", 600, 5)

        def slow_deny(*args, **kwargs):
            time.sleep(0.05)
            raise OAuthError("access_denied")

        def attempt():
            with pytest.raises(RuntimeError):
                provider.get_header()
            return True

        with (
            patch.object(provider._device, "request_device_code", return_value=da) as mock_req,
            patch.object(provider._device, "poll_token", side_effect=slow_deny),
            patch("shared_cache_auth.open_browser", return_value=False),
        ):
            assert _Concurrently(8)(attempt) == [True] * 8

        assert mock_req.call_count == 1, f"{mock_req.call_count} sign-ins for one failure"
