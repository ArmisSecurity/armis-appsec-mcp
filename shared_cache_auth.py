"""
Shared token cache + Device Auth provider for the AppSec MCP plugin.

``SharedCacheAuth`` is the credential path used when no client credentials
(``ARMIS_CLIENT_ID`` / ``ARMIS_CLIENT_SECRET``) are configured. It reuses the
OAuth2 tokens armis-cli caches in ``~/.armis/.sessions`` and, when that cache is
empty, runs the RFC 8628 browser device flow itself. See ``auth.init_auth`` for
how the provider is selected, and ``token_cache`` / ``device_auth`` for the
cross-process cache contract and the device-flow client.
"""

from __future__ import annotations

import logging
import os
import sys

from device_auth import (
    DEFAULT_DEVICE_CLIENT_ID,
    DeviceAuthorization,
    DeviceClient,
    OAuthError,
    open_browser,
)
from token_cache import StoredToken, TokenStore

logger = logging.getLogger("appsec-mcp")


class SharedCacheAuth:
    """Auth backed by the shared ``~/.armis/.sessions`` token cache.

    Lazy: nothing touches disk or the network in ``__init__`` (device flow
    stays out of server startup). On the first ``get_header()`` it resolves a
    usable access token in this order:

    1. In-memory token still valid (> 5 min remaining).
    2. Token loaded from the shared cache for this issuer, still valid.
    3. A refresh token in the cache -> refresh grant (rotated pair persisted).
    4. Nothing usable -> interactive browser device flow (needs ARMIS_TENANT_ID),
       result persisted to the shared cache for the CLI / other plugins.

    Fail-closed: a terminal failure raises ``RuntimeError`` (can't scan without
    auth), matching the fail-open/closed policy table in CLAUDE.md.

    Not thread-safe -- the MCP plugin processes tool calls sequentially.
    """

    def __init__(self, issuer: str, store: TokenStore | None = None):
        self._issuer = issuer
        self._store = store if store is not None else TokenStore()
        self._device = DeviceClient(issuer)
        self._token: StoredToken | None = None

    # ------------------------------------------------------------------
    # Token lifecycle
    # ------------------------------------------------------------------
    def get_header(self) -> str:
        """Return 'Bearer <token>', resolving/refreshing/logging-in as needed."""
        return f"Bearer {self._ensure_access_token()}"

    def _ensure_access_token(self) -> str:
        # 1. In-memory token still valid.
        if self._token is not None and self._token.is_valid():
            return self._token.access_token

        # 2. Load from the shared cache.
        cached = self._store.load(self._issuer)
        if cached is not None and cached.is_valid():
            self._token = cached
            return cached.access_token

        # 3. Refresh if we have a refresh token (from cache or memory).
        refresh_source = cached or self._token
        if refresh_source is not None and refresh_source.refresh_token:
            refreshed = self._refresh(refresh_source)
            if refreshed is not None:
                return refreshed.access_token

        # 4. Nothing usable -- run the interactive device flow.
        logged_in = self._device_login()
        return logged_in.access_token

    def _refresh(self, source: StoredToken) -> StoredToken | None:
        """Refresh via the rotated-refresh grant; persist the new pair.

        Returns None (falling through to a fresh login) when the session has
        expired server-side; raises for other refresh failures.
        """
        try:
            refreshed = self._device.refresh(source.refresh_token, source.client_id)
        except OAuthError as e:
            if e.code in ("invalid_grant", "expired_token"):
                logger.info("Shared session expired; falling back to interactive login.")
                return None
            raise RuntimeError(f"Failed to refresh Armis session: {e}") from e

        # Carry forward identity fields the refresh response may not echo.
        refreshed.tenant_id = refreshed.tenant_id or source.tenant_id
        refreshed.subject = refreshed.subject or source.subject
        refreshed.role = refreshed.role or source.role
        refreshed.region = refreshed.region or source.region
        refreshed.client_id = refreshed.client_id or source.client_id
        refreshed.issuer = refreshed.issuer or source.issuer

        self._token = refreshed
        self._persist(refreshed)
        return refreshed

    def _device_login(self) -> StoredToken:
        """Run the RFC 8628 browser device flow and persist the result."""
        tenant_id = os.environ.get("ARMIS_TENANT_ID", "")
        if not tenant_id:
            raise RuntimeError(
                "No Armis credentials found. Sign in with 'armis-cli auth login', "
                "or set ARMIS_CLIENT_ID / ARMIS_CLIENT_SECRET, or set ARMIS_TENANT_ID "
                "to let this plugin open a browser sign-in."
            )
        # The device-flow client_id is a public, non-secret identifier (RFC 8628
        # public client) -- no client_secret is ever involved. Use the same
        # hardcoded value armis-cli defaults to so the server recognizes it.
        client_id = DEFAULT_DEVICE_CLIENT_ID

        try:
            da = self._device.request_device_code(client_id, tenant_id)
        except (OAuthError, RuntimeError) as e:
            raise RuntimeError(f"Failed to start Armis sign-in: {e}") from e

        browse_url = da.verification_uri_complete or da.verification_uri
        opened = open_browser(browse_url) if browse_url else False
        self._print_verification_instructions(da, browse_url, opened)

        try:
            token = self._device.poll_token(da.device_code, client_id, da.interval, da.expires_in)
        except OAuthError as e:
            raise RuntimeError(f"Armis sign-in did not complete: {e}") from e

        token.issuer = token.issuer or self._issuer
        self._token = token
        self._persist(token)
        logger.info("Signed in via device flow; identity=%s", token.subject or "?")
        return token

    def _persist(self, token: StoredToken) -> None:
        """Best-effort write to the shared cache (in-memory token still valid)."""
        try:
            self._store.save(self._issuer, token)
        except (OSError, ValueError) as e:
            logger.warning("Could not persist token to shared cache: %s", e)

    @staticmethod
    def _print_verification_instructions(
        da: DeviceAuthorization, browse_url: str, opened: bool
    ) -> None:
        """Tell the user where to authenticate (stderr -- stdout is the MCP channel)."""
        if opened:
            print("Opened your browser to complete Armis sign-in.", file=sys.stderr)
            print(f"If it didn't open, visit:\n\n    {browse_url}\n", file=sys.stderr)
            print(f"Verify this code is shown: {da.user_code}\n", file=sys.stderr)
        else:
            print("To sign in to Armis, open the following URL in your browser:\n", file=sys.stderr)
            print(f"    {browse_url or da.verification_uri}\n", file=sys.stderr)
            print(f"and enter this code:  {da.user_code}\n", file=sys.stderr)

    # ------------------------------------------------------------------
    # Status for debug_config
    # ------------------------------------------------------------------
    def status(self) -> str:
        """Human-readable, token-free status label."""
        token = self._token or self._store.load(self._issuer)
        if token is None or not token.access_token:
            return "shared cache: not signed in"
        remaining = token.seconds_remaining()
        if remaining <= 0:
            if token.refresh_token:
                return "shared cache: access token expired (will refresh)"
            return "shared cache: expired"
        return f"shared cache: valid, expires in {int(remaining / 60)}m"
