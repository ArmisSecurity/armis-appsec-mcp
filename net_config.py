"""
Network setup for corporate environments: CA trust and proxy selection.

httpx ships with the certifi CA bundle and reads proxies only from env vars (plus
urllib's system fallback, which drops the system bypass list). Behind TLS
inspection (Zscaler, Netskope) or a system-configured proxy that breaks the
server even when the OS itself (and armis-cli) connect fine. Both functions here
run once at process startup, before any httpx client exists, and work by
adjusting the ``ssl`` module and the process environment — every
``httpx.post(...)`` call site then picks the result up via ``trust_env``.

CA trust precedence (first match wins):

1. ``SSL_CERT_FILE``  — explicit user choice; httpx honors it natively.
2. ``SSL_CERT_DIR``   — same.
3. ``REQUESTS_CA_BUNDLE`` — explicit user choice httpx does *not* read; exported
   as ``SSL_CERT_FILE`` (or ``SSL_CERT_DIR`` for a directory) so it takes effect.
   A path that does not exist is ignored (httpx never read it before).
4. OS certificate store via ``truststore.inject_into_ssl()`` (Windows cert store,
   macOS Keychain, system OpenSSL paths on Linux).
5. certifi — the httpx default, used if truststore is missing or fails.

An explicit bundle wins over the OS store because a user who set one has made a
deliberate choice (e.g. a corporate bundle that isn't in the OS store).

Proxy selection:

- If any of ``HTTPS_PROXY``/``HTTP_PROXY``/``ALL_PROXY`` (either case) is set, the
  environment is authoritative and nothing is changed (source ``env``).
- Otherwise the OS proxy (Windows registry / macOS System Settings) is read and,
  unless the API host is bypassed by ``NO_PROXY`` or the OS bypass list, exported
  as ``HTTPS_PROXY`` (source ``system``). When the host is bypassed, the host is
  appended to ``NO_PROXY`` so httpx's own system fallback can't re-apply it.
- PAC / WPAD auto-config is not supported; only a static proxy is read.

Fail-open: any error here leaves the httpx defaults in place.
"""

import logging
import os
import sys
import urllib.parse
import urllib.request
from collections.abc import Callable, MutableMapping
from dataclasses import dataclass

logger = logging.getLogger("appsec-mcp")

# Env vars that make the environment authoritative for proxy selection. Both cases
# because POSIX env is case-sensitive (Windows' os.environ is not).
PROXY_ENV_VARS = (
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "HTTP_PROXY",
    "http_proxy",
)
_SUPPORTED_PROXY_SCHEMES = {"http", "https"}


def mask_url(url: str) -> str:
    """Replace any ``user:password@`` in *url* with ``***@``.

    Proxy URLs commonly embed credentials; this is the only form in which a
    proxy URL may be logged or shown in debug_config output.
    """
    if not url:
        return url
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "<unparseable>"
    if "@" not in parts.netloc:
        return url
    host = parts.netloc.rsplit("@", 1)[1]
    return urllib.parse.urlunsplit(parts._replace(netloc=f"***@{host}"))


# ---------------------------------------------------------------------------
# CA trust
# ---------------------------------------------------------------------------
def _inject_truststore() -> None:
    import truststore

    truststore.inject_into_ssl()


def configure_ca_trust(
    environ: MutableMapping[str, str] | None = None,
    inject: Callable[[], None] = _inject_truststore,
) -> str:
    """Select the CA source (see module docstring) and return a label for it.

    Labels: ``SSL_CERT_FILE=<path>``, ``SSL_CERT_DIR=<path>``,
    ``REQUESTS_CA_BUNDLE=<path>``, ``truststore``, or ``certifi``.
    """
    env = os.environ if environ is None else environ

    for var in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        path = env.get(var)
        if path:
            if not os.path.exists(path):
                logger.warning("%s=%s does not exist; TLS verification will fail.", var, path)
            return f"{var}={path}"

    bundle = env.get("REQUESTS_CA_BUNDLE")
    if bundle:
        if os.path.exists(bundle):
            env["SSL_CERT_DIR" if os.path.isdir(bundle) else "SSL_CERT_FILE"] = bundle
            return f"REQUESTS_CA_BUNDLE={bundle}"
        # httpx never read REQUESTS_CA_BUNDLE, so a stale value used to be harmless.
        # Exporting a missing path as SSL_CERT_FILE would fail every request.
        logger.warning("REQUESTS_CA_BUNDLE=%s does not exist; ignoring it.", bundle)

    try:
        inject()
    except Exception as e:
        logger.warning("OS certificate store unavailable (%s); using certifi CA bundle.", e)
        return "certifi"
    return "truststore"


# ---------------------------------------------------------------------------
# Proxy
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ProxyChoice:
    source: str  # "none" | "env" | "system"
    url: str = ""  # effective proxy for HTTPS traffic, unmasked; "" when none
    note: str = ""

    def describe(self) -> str:
        """Masked one-line summary, e.g. ``system http://***@proxy:8080``."""
        parts = [self.source]
        if self.url:
            parts.append(mask_url(self.url))
        if self.note:
            parts.append(f"({self.note})")
        return " ".join(parts)


def _system_proxies() -> dict[str, str]:
    """OS-configured proxies, ignoring env vars.

    ``urllib.request.getproxies()`` returns the env config whenever *any* proxy
    env var is set (including a lone ``NO_PROXY``), so call the platform reader
    directly where there is one.
    """
    if sys.platform == "win32":
        return urllib.request.getproxies_registry()  # type: ignore[attr-defined]
    if sys.platform == "darwin":
        return urllib.request.getproxies_macosx_sysconf()  # type: ignore[attr-defined]
    return urllib.request.getproxies()


def _system_bypass(host: str) -> bool:
    """True if the OS proxy bypass list (Windows ProxyOverride / macOS exceptions)
    covers *host*."""
    if sys.platform == "win32":
        return bool(urllib.request.proxy_bypass_registry(host))  # type: ignore[attr-defined]
    if sys.platform == "darwin":
        return bool(urllib.request.proxy_bypass_macosx_sysconf(host))  # type: ignore[attr-defined]
    return False


def _env_no_proxy(env: MutableMapping[str, str]) -> str:
    return env.get("NO_PROXY") or env.get("no_proxy") or ""


def _append_no_proxy(env: MutableMapping[str, str], host: str) -> None:
    current = _env_no_proxy(env)
    env["NO_PROXY"] = f"{current},{host}" if current else host


def configure_proxy(
    api_url: str,
    environ: MutableMapping[str, str] | None = None,
    system_proxies: Callable[[], dict[str, str]] = _system_proxies,
    system_bypass: Callable[[str], bool] = _system_bypass,
) -> ProxyChoice:
    """Select the proxy for *api_url* (see module docstring) and apply it to env."""
    env = os.environ if environ is None else environ
    host = urllib.parse.urlsplit(api_url).hostname or ""
    no_proxy = _env_no_proxy(env)
    env_bypassed = bool(
        host and no_proxy and urllib.request.proxy_bypass_environment(host, {"no": no_proxy})  # type: ignore[attr-defined]
    )

    set_vars = [v for v in PROXY_ENV_VARS if env.get(v)]
    if set_vars:
        # httpx uses HTTPS_PROXY, then ALL_PROXY for https:// URLs; HTTP_PROXY
        # alone does not apply to the (HTTPS) API.
        https_url = next(
            (
                env[v]
                for v in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")
                if env.get(v)
            ),
            "",
        )
        if not https_url:
            return ProxyChoice("env", env[set_vars[0]], "HTTP_PROXY only; not used for https")
        if env_bypassed:
            return ProxyChoice("env", https_url, f"{host} bypassed by NO_PROXY")
        return ProxyChoice("env", https_url)

    try:
        proxies = system_proxies()
    except Exception as e:
        logger.warning("Could not read system proxy settings: %s", e)
        return ProxyChoice("none")
    url = proxies.get("https") or proxies.get("all") or ""
    if not url:
        return ProxyChoice("none")
    if "://" not in url:
        url = f"http://{url}"

    if env_bypassed:
        return ProxyChoice("none", note=f"system proxy {mask_url(url)} bypassed by NO_PROXY")
    try:
        bypassed = bool(host) and system_bypass(host)
    except Exception as e:
        logger.warning("Could not read system proxy bypass list: %s", e)
        bypassed = False
    if bypassed:
        _append_no_proxy(env, host)
        return ProxyChoice("none", note=f"system proxy {mask_url(url)} bypassed for {host}")

    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in _SUPPORTED_PROXY_SCHEMES:
        # httpx can't use it (e.g. socks4 from the registry) and would raise on
        # every request; pin the API host to a direct connection instead.
        if host:
            _append_no_proxy(env, host)
        return ProxyChoice("none", note=f"unsupported system proxy scheme {scheme!r} ignored")

    env["HTTPS_PROXY"] = url
    return ProxyChoice("system", url)
