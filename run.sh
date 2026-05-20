#!/usr/bin/env bash
PLUGIN_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$PLUGIN_DIR/.venv"
REQS_FILE="$PLUGIN_DIR/requirements.txt"
DEPS_SENTINEL="$VENV_DIR/.deps-installed"

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

if [ "$NEEDS_INSTALL" -eq 1 ]; then
    python3 -m venv "$VENV_DIR" || { echo "ERROR: python3 -m venv failed. Is python3 installed?" >&2; exit 1; }
    "$VENV_DIR/bin/pip" install -r "$REQS_FILE" --quiet || { echo "ERROR: pip install failed. Check requirements.txt and network connectivity." >&2; exit 1; }
    if [ -n "$REQS_HASH" ]; then
        printf '%s\n' "$REQS_HASH" > "$DEPS_SENTINEL"
    else
        touch "$DEPS_SENTINEL"
    fi
fi

# Pre-flight: check credentials exist (env vars OR .env file)
ENV_FILE="$PLUGIN_DIR/.env"
if [ -z "${ARMIS_CLIENT_ID:-}" ] || [ -z "${ARMIS_CLIENT_SECRET:-}" ]; then
    if [ ! -f "$ENV_FILE" ]; then
        MISSING=""
        [ -z "${ARMIS_CLIENT_ID:-}" ] && MISSING="ARMIS_CLIENT_ID"
        [ -z "${ARMIS_CLIENT_SECRET:-}" ] && MISSING="${MISSING:+$MISSING, }ARMIS_CLIENT_SECRET"
        echo "ERROR: $MISSING not set and .env not found at $ENV_FILE" >&2
        echo "  Either export ARMIS_CLIENT_ID/ARMIS_CLIENT_SECRET, or create .env:" >&2
        echo "    ARMIS_CLIENT_ID=<your-id>" >&2
        echo "    ARMIS_CLIENT_SECRET=<your-secret>" >&2
        echo "  Contact the Armis AppSec team for credentials." >&2
        exit 1
    fi
    if ! grep -qE '^ARMIS_CLIENT_ID=' "$ENV_FILE" 2>/dev/null; then
        echo "ERROR: ARMIS_CLIENT_ID not found in $ENV_FILE" >&2
        exit 1
    fi
    if ! grep -qE '^ARMIS_CLIENT_SECRET=' "$ENV_FILE" 2>/dev/null; then
        echo "ERROR: ARMIS_CLIENT_SECRET not found in $ENV_FILE" >&2
        exit 1
    fi
fi

exec "$VENV_DIR/bin/python" "$PLUGIN_DIR/server.py"
