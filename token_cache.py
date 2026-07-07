"""
Shared token cache for the AppSec MCP plugin.

This is a Python port of armis-cli's ``internal/auth/tokenstore.go``. The token
file ``~/.armis/.sessions`` is a **cross-process wire contract** shared with the
other Armis developer tools (armis-cli, and the future armis-knowledge MCP
plugin). Every tool reads and writes the SAME file so a single
``armis-cli auth login`` (or a first plugin scan) keeps every tool authenticated.

DO NOT change the path or JSON schema casually. Because the backend rotates
refresh tokens with reuse-detection, a divergent second store would replay a
rotated token and get the whole token family revoked. There must be a single
source of truth.

FILE SHAPE -- a JSON array of per-environment entries, so one machine can hold
tokens for several Armis environments at once (prod, dev, a local stack)::

    [
      {"env": "https://moose.armis.com", "token": { ...StoredToken... }},
      {"env": "http://localhost:8001",   "token": { ...StoredToken... }}
    ]

``env`` is the OAuth2 *issuer root* (the API base URL with any ``/api/vN``
suffix stripped) the token was obtained from -- the lookup key.

At rest: 0600 file inside a 0700 ``~/.armis``. On Windows the mode bits are a
no-op (confidentiality relies on the %USERPROFILE% ACL), same as armis-cli.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

logger = logging.getLogger("appsec-mcp")

# Cross-process contract constants -- must match armis-cli/internal/auth/tokenstore.go
_TOKEN_STORE_DIR_NAME = ".armis"  # noqa: S105 -- dir name, not a credential
_TOKEN_STORE_FILE_NAME = ".sessions"  # noqa: S105 -- filename, not a credential
_TOKEN_SCHEMA_VERSION = 1
_MAX_TOKEN_FILE_SIZE = 1 << 20  # 1 MiB

# Refresh when less than 5 minutes remain (matches armis-cli + JWTAuth).
_REFRESH_BUFFER_SECONDS = 300

# Strip a trailing REST-API version segment ("/api/v1", "/api/v2", ...) so the
# store key is the OAuth2 issuer root, which is what armis-cli keys on.
_API_VERSION_SUFFIX = re.compile(r"/api/v\d+/?$")


def normalize_env(env: str) -> str:
    """Canonicalize an environment key (mirror Go's ``normalizeEnv``).

    Trivially different spellings (a trailing slash, surrounding whitespace)
    must resolve to the same entry.
    """
    return env.strip().rstrip("/")


def issuer_from_api_url(api_url: str) -> str:
    """Derive the OAuth2 issuer root (the token-store env key) from an API URL.

    The scanner talks to ``{issuer}/api/v1``; armis-cli keys the shared cache on
    the issuer root (``https://moose.armis.com``, ``http://localhost:8001``). So
    strip a trailing ``/api/vN`` and normalize.
    """
    stripped = _API_VERSION_SUFFIX.sub("", api_url.strip())
    return normalize_env(stripped)


def _parse_expires_at(raw: str) -> datetime:
    """Parse an RFC3339 timestamp (Go ``time.Time`` JSON) into an aware datetime.

    Python 3.12's ``datetime.fromisoformat`` accepts the trailing ``Z``, numeric
    offsets, and fractional seconds Go emits. A naive result (no tzinfo) is
    treated as UTC so comparisons against ``datetime.now(timezone.utc)`` work.
    """
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


@dataclass
class StoredToken:
    """The persisted result of a device-flow login.

    Field names map 1:1 to the JSON keys armis-cli writes (snake_case). Add
    fields rather than renaming -- older readers must keep parsing new files.
    """

    access_token: str = ""
    refresh_token: str = ""
    expires_at: datetime | None = None
    tenant_id: str = ""
    subject: str = ""
    role: str = ""
    issuer: str = ""
    region: str = ""
    client_id: str = ""
    schema_version: int = _TOKEN_SCHEMA_VERSION

    @classmethod
    def from_dict(cls, data: dict) -> StoredToken:
        """Build a StoredToken from a parsed JSON object (tolerant of extras)."""
        expires_raw = data.get("expires_at")
        expires_at: datetime | None = None
        if expires_raw:
            try:
                expires_at = _parse_expires_at(expires_raw)
            except (ValueError, TypeError):
                expires_at = None
        return cls(
            access_token=data.get("access_token", "") or "",
            refresh_token=data.get("refresh_token", "") or "",
            expires_at=expires_at,
            tenant_id=data.get("tenant_id", "") or "",
            subject=data.get("subject", "") or "",
            role=data.get("role", "") or "",
            issuer=data.get("issuer", "") or "",
            region=data.get("region", "") or "",
            client_id=data.get("client_id", "") or "",
            schema_version=data.get("schema_version", _TOKEN_SCHEMA_VERSION),
        )

    def to_dict(self) -> dict:
        """Serialize to the JSON shape armis-cli expects (RFC3339 ``expires_at``)."""
        expires_str = ""
        if self.expires_at is not None:
            dt = self.expires_at
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            # Match Go's RFC3339: use 'Z' for UTC, otherwise a numeric offset.
            expires_str = dt.isoformat().replace("+00:00", "Z")
        return {
            "schema_version": self.schema_version,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": expires_str,
            "tenant_id": self.tenant_id,
            "subject": self.subject,
            "role": self.role,
            "issuer": self.issuer,
            "region": self.region,
            "client_id": self.client_id,
        }

    def seconds_remaining(self) -> float:
        """Seconds until expiry (negative if already expired, 0 if unknown)."""
        if self.expires_at is None:
            return 0.0
        return (self.expires_at - datetime.now(UTC)).total_seconds()

    def is_valid(self, buffer_seconds: int = _REFRESH_BUFFER_SECONDS) -> bool:
        """True when there is a usable access token with > ``buffer`` left."""
        if not self.access_token or self.expires_at is None:
            return False
        return self.seconds_remaining() > buffer_seconds


@dataclass
class _TokenEntry:
    env: str
    token: StoredToken | None = field(default=None)


class TokenStore:
    """Persists OAuth tokens to a 0600 file under ~/.armis, keyed by environment.

    Mirrors armis-cli's ``TokenStore``. ``dir`` overrides the directory holding
    the token file (tests only); empty means ``~/.armis``.
    """

    def __init__(self, dir: str | None = None):
        self._dir = dir

    def path(self) -> str:
        """Resolve the token-file path: ``<dir>/.sessions`` (dir = override or ~/.armis)."""
        base = self._dir
        if not base:
            base = os.path.join(os.path.expanduser("~"), _TOKEN_STORE_DIR_NAME)
        return os.path.join(base, _TOKEN_STORE_FILE_NAME)

    def load(self, env: str) -> StoredToken | None:
        """Return the stored token for ``env``, or None when absent.

        A missing, corrupted, or oversized file is treated as "no token" so a
        bad file never breaks credential resolution -- callers fall through to
        the next credential source (fail-open).
        """
        env = normalize_env(env)
        entries = self._read()
        for entry in entries:
            if normalize_env(entry.env) == env:
                tok = entry.token
                if tok is None or (not tok.access_token and not tok.refresh_token):
                    return None
                return tok
        return None

    def save(self, env: str, tok: StoredToken) -> None:
        """Insert or replace the token for ``env``, preserving other entries."""
        if not env:
            raise ValueError("env is required to store a token")
        tok.schema_version = _TOKEN_SCHEMA_VERSION
        env = normalize_env(env)

        entries = self._read()
        replaced = False
        for entry in entries:
            if normalize_env(entry.env) == env:
                entry.token = tok
                replaced = True
                break
        if not replaced:
            entries.append(_TokenEntry(env=env, token=tok))
        self._write(entries)

    # ------------------------------------------------------------------
    # Internal IO
    # ------------------------------------------------------------------
    def _read(self) -> list[_TokenEntry]:
        """Load and parse the token file. Missing/corrupt/oversized -> []."""
        path = self.path()
        try:
            size = os.path.getsize(path)
        except OSError:
            return []  # missing file
        if size > _MAX_TOKEN_FILE_SIZE:
            logger.warning("Token file %s exceeds %d bytes; ignoring.", path, _MAX_TOKEN_FILE_SIZE)
            return []
        try:
            with open(path, encoding="utf-8") as f:
                data = f.read()
        except OSError:
            return []
        if not data.strip():
            return []
        try:
            raw_entries = json.loads(data)
        except (json.JSONDecodeError, ValueError):
            logger.warning("Token file %s is not valid JSON; ignoring.", path)
            return []
        if not isinstance(raw_entries, list):
            return []
        entries: list[_TokenEntry] = []
        for raw in raw_entries:
            if not isinstance(raw, dict):
                continue
            env = raw.get("env", "")
            tok_raw = raw.get("token")
            token = StoredToken.from_dict(tok_raw) if isinstance(tok_raw, dict) else None
            entries.append(_TokenEntry(env=env, token=token))
        return entries

    def _write(self, entries: list[_TokenEntry]) -> None:
        """Persist entries to the 0600 file, creating ~/.armis (0700) if needed."""
        path = self.path()
        payload = [{"env": e.env, "token": e.token.to_dict() if e.token else None} for e in entries]
        data = json.dumps(payload, indent=2)
        directory = os.path.dirname(path)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        # Write then chmod: the file may pre-exist with looser perms.
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
        try:
            os.chmod(path, 0o600)
        except OSError:
            # Best-effort on platforms where chmod is a no-op (Windows).
            pass
        # Best-effort tighten the directory too (matches Go's 0700 intent).
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass


# Re-exported for callers that need the buffer (kept in one place).
REFRESH_BUFFER_SECONDS = _REFRESH_BUFFER_SECONDS
