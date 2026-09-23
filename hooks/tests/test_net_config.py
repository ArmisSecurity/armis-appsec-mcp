"""Tests for net_config.py — CA-source precedence, proxy selection, URL masking."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import net_config
from net_config import ProxyChoice, configure_ca_trust, configure_proxy, mask_url

API_URL = "https://moose.armis.com/api/v1"


def _no_system_proxy():
    return {}


def _never_bypass(host):
    return False


# ---------------------------------------------------------------------------
# mask_url
# ---------------------------------------------------------------------------
class TestMaskUrl:
    def test_masks_user_and_password(self):
        assert mask_url("http://alice:s3cret@proxy.corp:8080") == "http://***@proxy.corp:8080"

    def test_masks_user_only(self):
        assert mask_url("http://alice@proxy.corp:8080/") == "http://***@proxy.corp:8080/"

    def test_password_containing_at_sign(self):
        masked = mask_url("http://alice:p@ss@proxy.corp:3128")
        assert masked == "http://***@proxy.corp:3128"
        assert "p@ss" not in masked

    def test_no_userinfo_unchanged(self):
        assert mask_url("http://proxy.corp:8080") == "http://proxy.corp:8080"

    def test_empty(self):
        assert mask_url("") == ""

    def test_describe_masks(self):
        choice = ProxyChoice("system", "http://bob:hunter2@proxy:3128")
        assert choice.describe() == "system http://***@proxy:3128"
        assert "hunter2" not in choice.describe()


# ---------------------------------------------------------------------------
# configure_ca_trust
# ---------------------------------------------------------------------------
class TestCaTrustPrecedence:
    def test_ssl_cert_file_wins_and_skips_truststore(self, tmp_path):
        bundle = tmp_path / "ca.pem"
        bundle.write_text("x")
        env = {"SSL_CERT_FILE": str(bundle), "REQUESTS_CA_BUNDLE": "/other.pem"}
        calls = []
        assert configure_ca_trust(env, inject=lambda: calls.append(1)) == f"SSL_CERT_FILE={bundle}"
        assert calls == []
        assert env["SSL_CERT_FILE"] == str(bundle)

    def test_ssl_cert_dir(self, tmp_path):
        env = {"SSL_CERT_DIR": str(tmp_path)}
        calls = []
        assert configure_ca_trust(env, inject=lambda: calls.append(1)) == f"SSL_CERT_DIR={tmp_path}"
        assert calls == []

    def test_requests_ca_bundle_exported_as_ssl_cert_file(self, tmp_path):
        bundle = tmp_path / "corp.pem"
        bundle.write_text("x")
        env = {"REQUESTS_CA_BUNDLE": str(bundle)}
        calls = []
        result = configure_ca_trust(env, inject=lambda: calls.append(1))
        assert result == f"REQUESTS_CA_BUNDLE={bundle}"
        assert env["SSL_CERT_FILE"] == str(bundle)  # httpx reads this one
        assert calls == []

    def test_requests_ca_bundle_directory_exported_as_ssl_cert_dir(self, tmp_path):
        env = {"REQUESTS_CA_BUNDLE": str(tmp_path)}
        configure_ca_trust(env, inject=lambda: None)
        assert env["SSL_CERT_DIR"] == str(tmp_path)
        assert "SSL_CERT_FILE" not in env

    def test_missing_explicit_file_still_respected(self, tmp_path, caplog):
        missing = str(tmp_path / "nope.pem")
        env = {"SSL_CERT_FILE": missing}
        assert configure_ca_trust(env, inject=lambda: None) == f"SSL_CERT_FILE={missing}"
        assert "does not exist" in caplog.text

    def test_truststore_when_nothing_explicit(self):
        calls = []
        assert configure_ca_trust({}, inject=lambda: calls.append(1)) == "truststore"
        assert calls == [1]

    def test_certifi_fallback_when_truststore_fails(self, caplog):
        def boom():
            raise ImportError("No module named 'truststore'")

        assert configure_ca_trust({}, inject=boom) == "certifi"
        assert "certifi" in caplog.text

    def test_empty_values_ignored(self):
        env = {"SSL_CERT_FILE": "", "REQUESTS_CA_BUNDLE": ""}
        assert configure_ca_trust(env, inject=lambda: None) == "truststore"


# ---------------------------------------------------------------------------
# configure_proxy
# ---------------------------------------------------------------------------
class TestProxyFromEnv:
    @pytest.mark.parametrize("var", ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"])
    def test_env_proxy_is_authoritative(self, var):
        env = {var: "http://proxy.corp:8080"}

        def must_not_be_called():
            raise AssertionError("system proxy must not be consulted")

        choice = configure_proxy(API_URL, env, system_proxies=must_not_be_called)
        assert choice == ProxyChoice("env", "http://proxy.corp:8080")
        assert env == {var: "http://proxy.corp:8080"}  # untouched

    def test_https_proxy_preferred_over_all_proxy(self):
        env = {"ALL_PROXY": "http://all:1", "HTTPS_PROXY": "http://https:2"}
        assert configure_proxy(API_URL, env).url == "http://https:2"

    def test_http_proxy_only_noted(self):
        env = {"HTTP_PROXY": "http://proxy.corp:8080"}
        choice = configure_proxy(API_URL, env, system_proxies=_no_system_proxy)
        assert choice.source == "env"
        assert "not used for https" in choice.note
        assert "HTTPS_PROXY" not in env

    def test_env_proxy_bypassed_by_no_proxy(self):
        env = {"HTTPS_PROXY": "http://proxy:8080", "NO_PROXY": ".armis.com"}
        choice = configure_proxy(API_URL, env)
        assert choice.source == "env"
        assert "bypassed by NO_PROXY" in choice.note

    def test_env_proxy_describe_masks_credentials(self):
        env = {"HTTPS_PROXY": "http://u:topsecret@proxy:8080"}
        described = configure_proxy(API_URL, env).describe()
        assert "topsecret" not in described
        assert described == "env http://***@proxy:8080"


class TestProxyFromSystem:
    def test_no_env_no_system(self):
        env: dict[str, str] = {}
        assert configure_proxy(API_URL, env, _no_system_proxy, _never_bypass) == ProxyChoice("none")
        assert env == {}

    def test_system_https_proxy_exported(self):
        env: dict[str, str] = {}
        choice = configure_proxy(
            API_URL, env, lambda: {"https": "http://proxy.corp:8080"}, _never_bypass
        )
        assert choice == ProxyChoice("system", "http://proxy.corp:8080")
        assert env["HTTPS_PROXY"] == "http://proxy.corp:8080"

    def test_system_proxy_used_even_with_lone_no_proxy(self):
        # A lone NO_PROXY makes urllib.getproxies() skip the registry, so httpx
        # alone would silently go direct.
        env = {"NO_PROXY": "localhost"}
        choice = configure_proxy(
            API_URL, env, lambda: {"https": "http://proxy.corp:8080"}, _never_bypass
        )
        assert choice.source == "system"
        assert env["HTTPS_PROXY"] == "http://proxy.corp:8080"

    def test_all_scheme_fallback_and_bare_host(self):
        env: dict[str, str] = {}
        choice = configure_proxy(API_URL, env, lambda: {"all": "proxy.corp:3128"}, _never_bypass)
        assert choice.url == "http://proxy.corp:3128"
        assert env["HTTPS_PROXY"] == "http://proxy.corp:3128"

    def test_http_only_system_proxy_ignored(self):
        env: dict[str, str] = {}
        choice = configure_proxy(API_URL, env, lambda: {"http": "http://p:1"}, _never_bypass)
        assert choice.source == "none"
        assert "HTTPS_PROXY" not in env

    def test_no_proxy_env_bypasses_system_proxy(self):
        env = {"no_proxy": "moose.armis.com"}
        choice = configure_proxy(API_URL, env, lambda: {"https": "http://p:1"}, _never_bypass)
        assert choice.source == "none"
        assert "bypassed by NO_PROXY" in choice.note
        assert "HTTPS_PROXY" not in env

    def test_os_bypass_list_pins_direct(self):
        env: dict[str, str] = {}
        seen = []

        def bypass(host):
            seen.append(host)
            return True

        choice = configure_proxy(API_URL, env, lambda: {"https": "http://p:1"}, bypass)
        assert seen == ["moose.armis.com"]
        assert choice.source == "none"
        assert "HTTPS_PROXY" not in env
        # httpx's own registry fallback must not re-apply the proxy.
        assert env["NO_PROXY"] == "moose.armis.com"

    def test_os_bypass_appends_to_existing_no_proxy(self):
        env = {"NO_PROXY": "localhost"}
        configure_proxy(API_URL, env, lambda: {"https": "http://p:1"}, lambda h: True)
        assert env["NO_PROXY"] == "localhost,moose.armis.com"

    def test_unsupported_scheme_goes_direct(self):
        env: dict[str, str] = {}
        choice = configure_proxy(API_URL, env, lambda: {"https": "socks4://p:1080"}, _never_bypass)
        assert choice.source == "none"
        assert "socks4" in choice.note
        assert "HTTPS_PROXY" not in env
        assert env["NO_PROXY"] == "moose.armis.com"

    def test_system_reader_error_fails_open(self):
        def boom():
            raise OSError("registry unavailable")

        env: dict[str, str] = {}
        assert configure_proxy(API_URL, env, boom, _never_bypass) == ProxyChoice("none")
        assert env == {}

    def test_bypass_reader_error_still_uses_proxy(self):
        def boom(host):
            raise OSError("bad ProxyOverride")

        env: dict[str, str] = {}
        choice = configure_proxy(API_URL, env, lambda: {"https": "http://p:1"}, boom)
        assert choice.source == "system"

    def test_system_proxy_note_masks_credentials(self):
        choice = configure_proxy(
            API_URL, {}, lambda: {"https": "http://u:pw123@p:1"}, lambda h: True
        )
        assert "pw123" not in choice.describe()


class TestPlatformReaders:
    def test_windows_uses_registry(self, monkeypatch):
        monkeypatch.setattr(net_config.sys, "platform", "win32")
        monkeypatch.setattr(
            net_config.urllib.request,
            "getproxies_registry",
            lambda: {"https": "http://reg:8080"},
            raising=False,
        )
        monkeypatch.setattr(
            net_config.urllib.request, "proxy_bypass_registry", lambda h: True, raising=False
        )
        assert net_config._system_proxies() == {"https": "http://reg:8080"}
        assert net_config._system_bypass("moose.armis.com") is True

    def test_linux_has_no_system_bypass(self, monkeypatch):
        monkeypatch.setattr(net_config.sys, "platform", "linux")
        assert net_config._system_bypass("moose.armis.com") is False


def test_missing_requests_ca_bundle_is_ignored(tmp_path, caplog):
    missing = str(tmp_path / "nope.pem")
    env = {"REQUESTS_CA_BUNDLE": missing}
    assert configure_ca_trust(env, inject=lambda: None) == "truststore"
    assert "SSL_CERT_FILE" not in env
    assert "ignoring" in caplog.text
