"""Tests for token_cache.py — the shared ~/.armis/.sessions token cache.

This is the cross-process wire contract shared with armis-cli, so the JSON
shape and env-key semantics are asserted explicitly against what the Go
tokenstore writes.
"""

import json
import os
import stat
import sys
from datetime import UTC, datetime, timedelta

import pytest

_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from token_cache import (
    StoredToken,
    TokenStore,
    issuer_from_api_url,
    normalize_env,
)


def _future(seconds: int = 3600) -> datetime:
    return datetime.now(UTC) + timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# issuer_from_api_url / normalize_env
# ---------------------------------------------------------------------------
class TestIssuerFromApiUrl:
    def test_prod(self):
        assert issuer_from_api_url("https://moose.armis.com/api/v1") == "https://moose.armis.com"

    def test_dev(self):
        assert (
            issuer_from_api_url("https://moose-dev.armis.com/api/v1")
            == "https://moose-dev.armis.com"
        )

    def test_localhost(self):
        assert issuer_from_api_url("http://localhost:8001/api/v1") == "http://localhost:8001"

    def test_trailing_slash_and_v2(self):
        assert issuer_from_api_url("https://moose.armis.com/api/v2/") == "https://moose.armis.com"

    def test_no_version_suffix_left_alone(self):
        assert issuer_from_api_url("https://moose.armis.com/") == "https://moose.armis.com"

    def test_whitespace_trimmed(self):
        assert (
            issuer_from_api_url("  https://moose.armis.com/api/v1  ") == "https://moose.armis.com"
        )


class TestNormalizeEnv:
    def test_trailing_slash_and_space(self):
        assert normalize_env("  https://moose.armis.com/ ") == "https://moose.armis.com"


# ---------------------------------------------------------------------------
# StoredToken (de)serialization
# ---------------------------------------------------------------------------
class TestStoredTokenSerialization:
    def test_round_trip(self):
        tok = StoredToken(
            access_token="a",
            refresh_token="r",
            expires_at=datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC),
            tenant_id="t",
            subject="s",
            role="developer",
            issuer="https://moose.armis.com",
            region="us1",
            client_id="armis-cli",
        )
        d = tok.to_dict()
        assert d["schema_version"] == 1
        assert d["expires_at"] == "2030-01-02T03:04:05Z"
        back = StoredToken.from_dict(d)
        assert back.access_token == "a"
        assert back.refresh_token == "r"
        assert back.expires_at == tok.expires_at
        assert back.tenant_id == "t"
        assert back.region == "us1"

    def test_parses_go_rfc3339_variants(self):
        for raw, expect_valid in [
            ("2030-01-02T03:04:05Z", True),
            ("2030-01-02T03:04:05.123456789Z", True),
            ("2030-01-02T03:04:05+02:00", True),
        ]:
            tok = StoredToken.from_dict({"access_token": "a", "expires_at": raw})
            assert tok.expires_at is not None
            assert tok.is_valid() is expect_valid

    def test_bad_expires_at_becomes_none(self):
        tok = StoredToken.from_dict({"access_token": "a", "expires_at": "not-a-date"})
        assert tok.expires_at is None
        assert tok.is_valid() is False

    def test_is_valid_respects_buffer(self):
        # 2 minutes left, default 5-minute buffer -> not valid.
        tok = StoredToken(access_token="a", expires_at=_future(120))
        assert tok.is_valid() is False
        assert tok.is_valid(buffer_seconds=60) is True

    def test_is_valid_false_without_access_token(self):
        assert StoredToken(access_token="", expires_at=_future()).is_valid() is False


# ---------------------------------------------------------------------------
# TokenStore load/save
# ---------------------------------------------------------------------------
class TestTokenStore:
    def test_save_then_load(self, tmp_path):
        store = TokenStore(dir=str(tmp_path))
        tok = StoredToken(access_token="a", refresh_token="r", expires_at=_future())
        store.save("https://moose.armis.com", tok)

        loaded = store.load("https://moose.armis.com")
        assert loaded is not None
        assert loaded.access_token == "a"
        assert loaded.refresh_token == "r"

    def test_load_missing_returns_none(self, tmp_path):
        assert TokenStore(dir=str(tmp_path)).load("https://moose.armis.com") is None

    def test_file_shape_matches_contract(self, tmp_path):
        store = TokenStore(dir=str(tmp_path))
        store.save("https://moose.armis.com", StoredToken(access_token="a", expires_at=_future()))

        raw = json.loads((tmp_path / ".sessions").read_text())
        assert isinstance(raw, list)
        assert raw[0]["env"] == "https://moose.armis.com"
        assert raw[0]["token"]["schema_version"] == 1
        assert raw[0]["token"]["access_token"] == "a"

    def test_save_preserves_other_environments(self, tmp_path):
        store = TokenStore(dir=str(tmp_path))
        store.save(
            "https://moose.armis.com", StoredToken(access_token="prod", expires_at=_future())
        )
        store.save("http://localhost:8001", StoredToken(access_token="local", expires_at=_future()))

        assert store.load("https://moose.armis.com").access_token == "prod"
        assert store.load("http://localhost:8001").access_token == "local"
        raw = json.loads((tmp_path / ".sessions").read_text())
        assert len(raw) == 2

    def test_save_replaces_same_environment(self, tmp_path):
        store = TokenStore(dir=str(tmp_path))
        store.save("https://moose.armis.com", StoredToken(access_token="old", expires_at=_future()))
        store.save("https://moose.armis.com", StoredToken(access_token="new", expires_at=_future()))

        raw = json.loads((tmp_path / ".sessions").read_text())
        assert len(raw) == 1
        assert store.load("https://moose.armis.com").access_token == "new"

    def test_load_normalizes_env_key(self, tmp_path):
        store = TokenStore(dir=str(tmp_path))
        store.save("https://moose.armis.com", StoredToken(access_token="a", expires_at=_future()))
        # Trailing slash must resolve to the same entry.
        assert store.load("https://moose.armis.com/") is not None

    def test_empty_token_entry_treated_as_absent(self, tmp_path):
        (tmp_path / ".sessions").write_text(
            json.dumps([{"env": "https://moose.armis.com", "token": {"access_token": ""}}])
        )
        assert TokenStore(dir=str(tmp_path)).load("https://moose.armis.com") is None

    def test_corrupt_file_fails_open(self, tmp_path):
        (tmp_path / ".sessions").write_text("{ this is not json")
        assert TokenStore(dir=str(tmp_path)).load("https://moose.armis.com") is None

    def test_oversized_file_fails_open(self, tmp_path):
        (tmp_path / ".sessions").write_text("[]" + "x" * (1 << 20))
        assert TokenStore(dir=str(tmp_path)).load("https://moose.armis.com") is None

    def test_save_creates_dir_and_load_after(self, tmp_path):
        nested = tmp_path / "created_by_save"
        store = TokenStore(dir=str(nested))
        store.save("https://moose.armis.com", StoredToken(access_token="a", expires_at=_future()))
        assert (nested / ".sessions").is_file()

    @pytest.mark.skipif(os.name == "nt", reason="POSIX file modes only")
    def test_file_written_0600(self, tmp_path):
        store = TokenStore(dir=str(tmp_path))
        store.save("https://moose.armis.com", StoredToken(access_token="a", expires_at=_future()))
        mode = stat.S_IMODE(os.stat(tmp_path / ".sessions").st_mode)
        assert mode == 0o600

    def test_path_default_under_home(self):
        # No dir override -> ~/.armis/.sessions (do not read/write it here).
        path = TokenStore().path()
        assert path.endswith(os.path.join(".armis", ".sessions"))

    def test_save_empty_env_raises(self, tmp_path):
        with pytest.raises(ValueError, match="env is required"):
            TokenStore(dir=str(tmp_path)).save("", StoredToken(access_token="a"))
