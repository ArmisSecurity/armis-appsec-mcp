#!/usr/bin/env bash
PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$PLUGIN_DIR/.venv"
REQS_FILE="$PLUGIN_DIR/requirements.txt"
DEPS_SENTINEL="$VENV_DIR/.deps-installed"

# venv layout differs by platform: POSIX puts the interpreter under bin/,
# native Windows Python (e.g. via Git Bash) puts it under Scripts/.
venv_python() {
    if [ -f "$VENV_DIR/bin/python" ]; then
        printf '%s\n' "$VENV_DIR/bin/python"
    elif [ -f "$VENV_DIR/Scripts/python.exe" ]; then
        printf '%s\n' "$VENV_DIR/Scripts/python.exe"
    fi
}

venv_pip() {
    if [ -f "$VENV_DIR/bin/pip" ]; then
        printf '%s\n' "$VENV_DIR/bin/pip"
    elif [ -f "$VENV_DIR/Scripts/pip.exe" ]; then
        printf '%s\n' "$VENV_DIR/Scripts/pip.exe"
    fi
}

# Compute a hash of requirements.txt to detect changes.
REQS_HASH=""
if command -v sha256sum >/dev/null 2>&1; then
    REQS_HASH="$(sha256sum "$REQS_FILE" 2>/dev/null | cut -d ' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
    REQS_HASH="$(shasum -a 256 "$REQS_FILE" 2>/dev/null | cut -d ' ' -f1)"
fi

NEEDS_INSTALL=0
if [ ! -f "$DEPS_SENTINEL" ]; then
    NEEDS_INSTALL=1
elif [ -n "$REQS_HASH" ]; then
    STORED_HASH="$(cat "$DEPS_SENTINEL" 2>/dev/null || true)"
    if [ "$STORED_HASH" != "$REQS_HASH" ]; then
        NEEDS_INSTALL=1
    fi
fi

# Also reinstall if the venv's Python is broken (e.g. pyenv version switch, Homebrew upgrade).
# Running `python -c ""` is a cheap probe — it fails if the interpreter binary is gone/stale.
if [ "$NEEDS_INSTALL" -eq 0 ]; then
    VENV_PYTHON="$(venv_python)"
    if [ -z "$VENV_PYTHON" ] || ! "$VENV_PYTHON" -c "" >/dev/null 2>&1; then
        NEEDS_INSTALL=1
    fi
fi

if [ "$NEEDS_INSTALL" -eq 1 ]; then
    # Only a rebuild needs a system Python, so a healthy venv starts even when PATH has none.
    . "$PLUGIN_DIR/hooks/find-python.sh"
    if ! find_python all; then
        echo "ERROR: no working python3/python/py found on PATH." >&2
        exit 1
    fi
    # Remove existing venv entirely before recreating — re-running venv against an existing
    # directory with a different Python grafts a second lib/pythonX.Y tree while leaving
    # bin/python (or Scripts/python.exe) pointing at the original, causing
    # ModuleNotFoundError at runtime.
    rm -rf "$VENV_DIR"
    "$PYTHON_BIN" $PYTHON_ARGS -m venv "$VENV_DIR" || { echo "ERROR: $PYTHON_BIN $PYTHON_ARGS -m venv failed." >&2; exit 1; }
    VENV_PIP="$(venv_pip)"
    if [ -z "$VENV_PIP" ]; then
        echo "ERROR: no pip found in $VENV_DIR (checked bin/pip and Scripts/pip.exe) after venv creation." >&2
        exit 1
    fi
    "$VENV_PIP" install --prefer-binary -r "$REQS_FILE" --quiet || { echo "ERROR: pip install failed. Check requirements.txt and network connectivity." >&2; exit 1; }
    if [ -n "$REQS_HASH" ]; then
        printf '%s\n' "$REQS_HASH" > "$DEPS_SENTINEL"
    else
        touch "$DEPS_SENTINEL"
    fi
fi

# Pre-flight: catch a half-configured client-credentials setup early. Having no
# credentials at all is valid: auth.init_auth falls back to the shared token
# cache / Device Auth (SSO), so only a lone ID or SECRET is an error here.
# ARMIS_DEFAULT_AUTH_METHOD=sso ignores client credentials entirely, so skip.
ENV_FILE="$PLUGIN_DIR/.env"

# True if NAME is set in the environment or assigned in .env.
has_setting() {
    _val="${!1:-}"
    [ -n "$_val" ] && return 0
    [ -f "$ENV_FILE" ] && grep -qE "^$1=" "$ENV_FILE" 2>/dev/null
}

# Value of NAME from the environment, else .env (quotes stripped), lowercased.
setting_value() {
    _val="${!1:-}"
    if [ -z "$_val" ] && [ -f "$ENV_FILE" ]; then
        _val="$(grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d '=' -f2- | tr -d "\"'")"
    fi
    printf '%s\n' "$_val" | tr '[:upper:]' '[:lower:]'
}

if [ "$(setting_value ARMIS_DEFAULT_AUTH_METHOD)" != "sso" ]; then
    HAS_ID=0
    HAS_SECRET=0
    has_setting ARMIS_CLIENT_ID && HAS_ID=1
    has_setting ARMIS_CLIENT_SECRET && HAS_SECRET=1
    if [ "$HAS_ID" -ne "$HAS_SECRET" ]; then
        MISSING="ARMIS_CLIENT_SECRET"
        [ "$HAS_ID" -eq 0 ] && MISSING="ARMIS_CLIENT_ID"
        echo "ERROR: $MISSING is not set (env or $ENV_FILE) but the other client credential is." >&2
        echo "  Set both ARMIS_CLIENT_ID and ARMIS_CLIENT_SECRET, or remove both to sign in via SSO" >&2
        echo "  (set ARMIS_TENANT_ID for the first browser sign-in)." >&2
        exit 1
    fi
fi

VENV_PYTHON="$(venv_python)"
if [ -z "$VENV_PYTHON" ]; then
    echo "ERROR: no python interpreter found in $VENV_DIR (checked bin/python and Scripts/python.exe)." >&2
    exit 1
fi
exec "$VENV_PYTHON" "$PLUGIN_DIR/server.py"
