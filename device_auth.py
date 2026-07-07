"""
OAuth2 Device Authorization Grant (RFC 8628) client for the AppSec MCP plugin.

A Python port of the subset of armis-cli's ``internal/auth/device.go`` the
plugin needs: request a device code, poll the token endpoint until the user
approves in the browser, and refresh a rotated token pair. The server side is
the Moose OAuth2 authorization server, mounted at the issuer root
(``/oauth2/device``, ``/oauth2/token``) -- NOT under ``/api/v1``.

Tokens obtained here are written to the shared cache (``token_cache.TokenStore``)
so armis-cli and the other MCP plugins can reuse them, and vice versa.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx

from token_cache import StoredToken

logger = logging.getLogger("appsec-mcp")

# The public client_id armis-cli identifies as in the device flow. The plugin is
# a public client (no secret); security comes from the device_code and
# refresh-token rotation, not this identifier.
DEFAULT_DEVICE_CLIENT_ID = "armis-cli"

# Grant types (RFC 8628 §3.4 / RFC 6749 §6).
_GRANT_TYPE_DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
_GRANT_TYPE_REFRESH_TOKEN = "refresh_token"  # noqa: S105 -- grant-type name, not a secret

# Endpoints are root-mounted on the issuer per RFC 8628 / the backend router.
_DEVICE_ENDPOINT_PATH = "/oauth2/device"
_TOKEN_ENDPOINT_PATH = "/oauth2/token"  # noqa: S105 -- URL path, not a secret

# Polling guardrails so a misbehaving server cannot make us hammer it.
_MIN_POLL_INTERVAL = 1.0
_DEFAULT_POLL_INTERVAL = 5.0
_MAX_POLL_INTERVAL = 60.0

# OAuth2 error codes we branch on (RFC 8628 §3.5).
_ERR_AUTHORIZATION_PENDING = "authorization_pending"
_ERR_SLOW_DOWN = "slow_down"
_ERR_EXPIRED_TOKEN = "expired_token"  # noqa: S105 -- error code, not a secret
_ERR_ACCESS_DENIED = "access_denied"
_ERR_INVALID_GRANT = "invalid_grant"

_LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1"}

_HTTP_SCHEMES = {"http", "https"}

# Generous local backstop when the server omits the device-code ``expires_in``,
# so a broken response can't make us poll forever.
_BACKSTOP_DEADLINE_SECONDS = 900.0  # 15 minutes


class OAuthError(Exception):
    """A typed OAuth2 protocol error so callers can branch on ``code``."""

    def __init__(self, code: str, description: str = "", status_code: int = 0):
        self.code = code
        self.description = description
        self.status_code = status_code
        super().__init__(f"{code}: {description}" if description else code)


@dataclass
class DeviceAuthorization:
    """The RFC 8628 §3.2 device authorization response."""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


def open_browser(raw_url: str) -> bool:
    """Open ``raw_url`` in the default browser. Returns True on success.

    Only http(s) URLs are accepted, so a malformed verification URI cannot be
    turned into the execution of an arbitrary local handler. Never raises --
    callers fall back to printing the URL and user code.
    """
    try:
        parsed = urllib.parse.urlparse(raw_url)
    except ValueError:
        return False
    # armis:ignore cwe:601 cwe:78 reason:the http(s)-only guard below IS the
    # mitigation; raw_url is the verification URI from an HTTPS-verified,
    # operator-configured issuer (APPSEC_API_URL), not attacker input, and RFC
    # 8628 requires opening the server-provided URI. Mirrors armis-cli OpenBrowser.
    if parsed.scheme not in _HTTP_SCHEMES:
        return False
    try:
        return webbrowser.open(raw_url)
    except Exception:  # noqa: BLE001 -- headless/locked-down env; degrade gracefully
        return False


def _decode_jwt_claims(token: str) -> dict:
    """Decode (without verifying) a JWT payload into a claims dict.

    Signature verification is delegated to the backend, which validates every
    API request; we only read claims for local caching/refresh scheduling. The
    token comes from our own HTTPS-verified token endpoint.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid JWT format: expected 3 dot-separated parts")
    payload_b64 = parts[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)  # pad for base64url
    try:
        payload = base64.urlsafe_b64decode(payload_b64)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"invalid JWT payload encoding: {e}") from e
    return json.loads(payload)


class DeviceClient:
    """Talks to the OAuth2 device + token endpoints on the issuer.

    HTTPS is enforced for non-localhost hosts and redirects are disabled: the
    token endpoint carries the device_code and refresh_token, which must not be
    replayed to a redirect target.
    """

    def __init__(self, issuer: str, debug: bool = False):
        if not issuer:
            raise ValueError("issuer base URL is required for device authentication")
        parsed = urllib.parse.urlparse(issuer)
        if parsed.scheme != "https" and parsed.hostname not in _LOCALHOST_HOSTS:
            raise RuntimeError("OAuth2 issuer must use HTTPS (except localhost).")
        self._issuer = issuer.rstrip("/")
        self._debug = debug

    # ------------------------------------------------------------------
    # Device flow
    # ------------------------------------------------------------------
    def request_device_code(
        self, client_id: str, tenant_id: str, scope: str = ""
    ) -> DeviceAuthorization:
        """Perform the RFC 8628 §3.1 device authorization request."""
        if not tenant_id:
            raise ValueError("tenant_id is required to start the device authorization")
        form = {"client_id": client_id, "tenant_id": tenant_id}
        if scope:
            form["scope"] = scope

        body, status = self._post_form(_DEVICE_ENDPOINT_PATH, form)
        if status != 200:
            raise self._parse_error(body, status)

        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError) as e:
            raise RuntimeError(f"failed to parse device authorization response: {e}") from e

        da = DeviceAuthorization(
            device_code=data.get("device_code", ""),
            user_code=data.get("user_code", ""),
            verification_uri=data.get("verification_uri", ""),
            verification_uri_complete=data.get("verification_uri_complete", ""),
            expires_in=int(data.get("expires_in", 0) or 0),
            interval=int(data.get("interval", 0) or 0),
        )
        if not da.device_code or not da.user_code:
            raise RuntimeError("device authorization response missing required fields")
        return da

    def poll_token(
        self,
        device_code: str,
        client_id: str,
        interval_seconds: int,
        expires_in_seconds: int = 0,
    ) -> StoredToken:
        """Poll the token endpoint until approval, expiry, or denial.

        Honors the server's interval and backs off on ``slow_down``. The overall
        wait is bounded by the device code's ``expires_in`` (falling back to a
        generous local backstop when the server omitted it), so a broken server
        response can never make us poll forever.
        """
        interval = float(interval_seconds)
        if interval < _MIN_POLL_INTERVAL:
            interval = _DEFAULT_POLL_INTERVAL
        if interval > _MAX_POLL_INTERVAL:
            interval = _MAX_POLL_INTERVAL

        budget = float(expires_in_seconds) if expires_in_seconds > 0 else _BACKSTOP_DEADLINE_SECONDS
        deadline = time.monotonic() + budget
        while True:
            # Wait first: the spec requires waiting `interval` between polls, and
            # the authorization is never approved instantly anyway.
            if time.monotonic() + interval > deadline:
                raise OAuthError(
                    _ERR_EXPIRED_TOKEN,
                    "the login request expired before it was approved",
                )
            time.sleep(interval)
            try:
                return self._exchange_device_code(device_code, client_id)
            except OAuthError as oerr:
                if oerr.code == _ERR_AUTHORIZATION_PENDING:
                    continue
                if oerr.code == _ERR_SLOW_DOWN:
                    interval = min(interval + 5.0, _MAX_POLL_INTERVAL)
                    continue
                if oerr.code == _ERR_EXPIRED_TOKEN:
                    raise OAuthError(
                        _ERR_EXPIRED_TOKEN,
                        "the login request expired before it was approved; sign in again",
                    ) from oerr
                if oerr.code == _ERR_ACCESS_DENIED:
                    raise OAuthError(_ERR_ACCESS_DENIED, "the login request was denied") from oerr
                raise

    def refresh(self, refresh_token: str, client_id: str) -> StoredToken:
        """Exchange a refresh token for a fresh access/refresh pair (RFC 6749 §6).

        The backend rotates the refresh token, so the returned StoredToken
        carries a new refresh_token the caller must persist.
        """
        form = {"grant_type": _GRANT_TYPE_REFRESH_TOKEN, "refresh_token": refresh_token}
        if client_id:
            form["client_id"] = client_id
        return self._token_request(form, client_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _exchange_device_code(self, device_code: str, client_id: str) -> StoredToken:
        form = {
            "grant_type": _GRANT_TYPE_DEVICE_CODE,
            "device_code": device_code,
            "client_id": client_id,
        }
        return self._token_request(form, client_id)

    def _token_request(self, form: dict, client_id: str) -> StoredToken:
        body, status = self._post_form(_TOKEN_ENDPOINT_PATH, form)
        if status != 200:
            raise self._parse_error(body, status)

        try:
            tr = json.loads(body)
        except (json.JSONDecodeError, ValueError) as e:
            raise RuntimeError(f"failed to parse token response: {e}") from e

        access_token = tr.get("access_token", "")
        if not access_token:
            raise RuntimeError("token response missing access_token")

        try:
            claims = _decode_jwt_claims(access_token)
        except (ValueError, json.JSONDecodeError) as e:
            raise RuntimeError(f"failed to parse access token: {e}") from e

        # Prefer the server-provided expires_in; fall back to the token's exp.
        expires_at: datetime | None = None
        expires_in = tr.get("expires_in")
        if expires_in:
            expires_at = datetime.now(UTC) + timedelta(seconds=int(expires_in))
        elif claims.get("exp"):
            expires_at = datetime.fromtimestamp(float(claims["exp"]), tz=UTC)

        return StoredToken(
            access_token=access_token,
            refresh_token=tr.get("refresh_token", "") or "",
            expires_at=expires_at,
            tenant_id=claims.get("tenant_id", "") or "",
            subject=claims.get("sub", "") or "",
            role=claims.get("role", "") or "",
            issuer=claims.get("iss", "") or "",
            region=claims.get("region", "") or "",
            client_id=client_id,
        )

    def _post_form(self, path: str, form: dict) -> tuple[str, int]:
        """Issue a form-encoded POST; return ``(body_text, status_code)``."""
        url = self._issuer + path
        try:
            response = httpx.post(
                url,
                data=form,
                headers={"Accept": "application/json"},
                timeout=30.0,
                follow_redirects=False,
            )
        except httpx.TimeoutException as e:
            raise RuntimeError("request timed out contacting the authorization server") from e
        except httpx.HTTPError as e:
            raise RuntimeError(f"request failed: {e}") from e
        return response.text, response.status_code

    @staticmethod
    def _parse_error(body: str, status: int) -> Exception:
        """Convert an OAuth2 error body into a typed OAuthError."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            data = {}
        code = data.get("error")
        if code:
            return OAuthError(code, data.get("error_description", ""), status)
        return OAuthError("server_error", f"unexpected response (status {status})", status)
