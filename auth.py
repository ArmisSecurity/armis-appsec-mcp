"""
Authentication provider for the AppSec MCP plugin.

Supports two credential paths, resolved in ``init_auth``:

1. **Client credentials** (``JWTAuth``): exchange ARMIS_CLIENT_ID /
   ARMIS_CLIENT_SECRET for a short-lived Bearer token via
   POST /api/v1/auth/token (same flow as armis-cli). Token cached in memory,
   refreshed within 5 minutes of expiry. This path is unchanged and takes
   priority when both env vars are set (backward compatible).

2. **Shared token cache + Device Auth** (``SharedCacheAuth``, defined in
   ``shared_cache_auth.py``): when no client credentials are configured (or when
   ARMIS_DEFAULT_AUTH_METHOD=sso is set, which forces this path regardless of
   any client credentials), reuse the OAuth2 tokens armis-cli caches in
   ``~/.armis/.sessions`` (populated by ``armis-cli auth login`` or by this
   plugin's own RFC 8628 device flow). Access tokens are refreshed via the
   refresh-token grant; a fully-empty cache triggers an interactive browser
   login (needs ARMIS_TENANT_ID). See
   ``shared_cache_auth`` / ``token_cache`` / ``device_auth``.
"""

import base64
import json
import logging
import os
import time
import urllib.parse

import httpx

from shared_cache_auth import SharedCacheAuth
from token_cache import issuer_from_api_url

__all__ = [
    "JWTAuth",
    "SharedCacheAuth",
    "init_auth",
    "get_auth_header",
    "get_auth_status",
    "get_auth_method",
    "invalidate_auth",
]

logger = logging.getLogger("appsec-mcp")

# Refresh when less than 5 minutes remain (matches armis-cli)
_REFRESH_BUFFER_SECONDS = 300

_LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1"}


class JWTAuth:
    """In-memory JWT token manager.

    Not thread-safe. The MCP plugin processes tool calls sequentially,
    so concurrent access is not a concern.
    """

    def __init__(self, api_url: str, client_id: str):
        self._api_url = api_url
        self._client_id = client_id
        self._token: str | None = None
        self._expires_at: float = 0.0  # epoch seconds

    # ------------------------------------------------------------------
    # Token lifecycle
    # ------------------------------------------------------------------

    def exchange(self) -> None:
        """Exchange client credentials for a new JWT token."""
        url = f"{self._api_url.rstrip('/')}/auth/token"

        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" and parsed.hostname not in _LOCALHOST_HOSTS:
            raise RuntimeError("APPSEC_API_URL must use HTTPS (except localhost).")

        # CWE-522: Secret is read from env on each call (not cached in memory).
        # This is the standard OAuth2 client_credentials flow:
        # - HTTPS enforced above (except localhost for dev)
        # - Sent via POST body, not URL params or headers
        # - Env var trust: an attacker with env access already has code execution
        client_secret = os.environ.get("ARMIS_CLIENT_SECRET", "")
        if not client_secret:
            raise RuntimeError("ARMIS_CLIENT_SECRET is not set in environment.")

        try:
            response = httpx.post(
                url,
                json={
                    "client_id": self._client_id,
                    "client_secret": client_secret,
                    "region": None,
                },
                timeout=30.0,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise RuntimeError("Authentication failed: invalid client_id/client_secret") from e
            raise RuntimeError(f"Authentication failed: HTTP {e.response.status_code}") from e
        except httpx.TimeoutException as e:
            raise RuntimeError("Authentication failed: connection timeout") from e
        except Exception as e:
            raise RuntimeError(f"Authentication failed: {e}") from e

        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError) as e:
            raise RuntimeError("Authentication failed: invalid response (expected JSON)") from e

        if "token" not in data:
            raise RuntimeError("Authentication failed: unexpected response (missing token)")

        self._token = data["token"]
        try:
            self._expires_at = self._parse_jwt_exp(self._token)
        except (ValueError, KeyError) as e:
            self._token = None
            raise RuntimeError(f"Authentication failed: invalid JWT payload ({e})") from e
        logger.info("JWT token obtained, expires at %.0f", self._expires_at)

    def _is_valid(self) -> bool:
        return self._token is not None and time.time() < self._expires_at - _REFRESH_BUFFER_SECONDS

    def get_header(self) -> str:
        """Return 'Bearer <token>', exchanging/refreshing if needed."""
        if not self._is_valid():
            self.exchange()
        return f"Bearer {self._token}"

    def invalidate(self) -> None:
        """Drop the cached token so the next call re-exchanges credentials.

        Called after the scan API rejects the token with 401 (e.g. the token was
        revoked server-side before its local expiry).
        """
        self._token = None
        self._expires_at = 0.0

    # ------------------------------------------------------------------
    # JWT payload parsing
    #
    # No signature verification — the token is used as an opaque bearer
    # token. The server validates the signature on each API call. We only
    # read 'exp' to schedule local refresh. The token source is our own
    # HTTPS-verified auth endpoint (enforced in exchange()).
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_jwt_exp(token: str) -> float:
        """Extract the exp claim from a JWT payload."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format: expected 3 dot-separated parts")

        payload_b64 = parts[1]
        # Add padding for base64url decode
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = float(payload["exp"])

        # Bounds check: reject clearly invalid expiry values
        now = time.time()
        if exp <= now:
            raise ValueError("JWT exp is in the past")
        if exp > now + 86400:
            raise ValueError("JWT exp is more than 24h in the future")

        return exp

    # ------------------------------------------------------------------
    # Status for debug_config
    # ------------------------------------------------------------------

    def status(self) -> str:
        """Human-readable token status."""
        if self._token is None:
            return "not yet exchanged"
        remaining = self._expires_at - time.time()
        if remaining <= 0:
            return "expired"
        minutes = int(remaining / 60)
        return f"valid, expires in {minutes}m"


# ======================================================================
# Module-level singleton
# ======================================================================

_auth: JWTAuth | SharedCacheAuth | None = None


def _sso_requested() -> bool:
    """True when the user opted into SSO via ARMIS_DEFAULT_AUTH_METHOD=sso.

    Case-insensitive, whitespace-tolerant, matching armis-cli's
    ``shouldAutoLoginSSO``.
    """
    return os.environ.get("ARMIS_DEFAULT_AUTH_METHOD", "").strip().lower() == "sso"


def init_auth(api_url: str) -> None:
    """Resolve the auth provider from the environment.  Call once at startup.

    Priority (see module docstring):
      * ARMIS_DEFAULT_AUTH_METHOD=sso -> force the shared token cache + Device
        Auth path (``SharedCacheAuth``), even if client credentials are set.
        This is an explicit SSO opt-in, so client credentials are ignored;
      * both ARMIS_CLIENT_ID + ARMIS_CLIENT_SECRET set -> client-credentials
        (``JWTAuth``), unchanged and fully backward compatible;
      * exactly one set -> a clear partial-configuration error;
      * neither set -> shared token cache + Device Auth (``SharedCacheAuth``).

    ``SharedCacheAuth`` is constructed lazily (no disk/network here -- it reuses
    a cached token silently, refreshes it, or runs the browser device flow only
    on the first scan that actually needs auth).
    """
    global _auth

    # Explicit SSO opt-in wins over everything: the only credential path is the
    # shared cache / Device Auth (matches armis-cli ARMIS_DEFAULT_AUTH_METHOD=SSO).
    if _sso_requested():
        _auth = SharedCacheAuth(issuer_from_api_url(api_url))
        return

    client_id = os.environ.get("ARMIS_CLIENT_ID", "")
    client_secret = os.environ.get("ARMIS_CLIENT_SECRET", "")

    if client_id and client_secret:
        _auth = JWTAuth(api_url, client_id)
        return
    if client_id and not client_secret:
        raise RuntimeError("ARMIS_CLIENT_SECRET is not set (ARMIS_CLIENT_ID is set).")
    if client_secret and not client_id:
        raise RuntimeError("ARMIS_CLIENT_ID is not set (ARMIS_CLIENT_SECRET is set).")

    # No client credentials -> shared cache / Device Auth fallback.
    _auth = SharedCacheAuth(issuer_from_api_url(api_url))


def get_auth_header() -> str:
    """Return the Authorization header value."""
    if _auth is None:
        raise RuntimeError("Auth not initialized. Call init_auth() first.")
    return _auth.get_header()


def invalidate_auth() -> None:
    """Invalidate the current token so the next ``get_auth_header`` re-authenticates.

    Called by the scan path on an HTTP 401: the token the server rejected was
    accepted locally (unexpired) but the session was expired or revoked
    server-side, so it must be discarded and re-acquired (re-exchange for
    ``JWTAuth``; refresh or device login for ``SharedCacheAuth``).
    """
    if _auth is not None:
        _auth.invalidate()


def get_auth_status() -> str:
    """Return human-readable auth status for debug_config."""
    if _auth is None:
        return "not initialized"
    return _auth.status()


def get_auth_method() -> str:
    """Return the credential path in use, for debug_config."""
    if _auth is None:
        return "not initialized"
    if isinstance(_auth, JWTAuth):
        return "client-credentials"
    return "shared-cache/SSO"
