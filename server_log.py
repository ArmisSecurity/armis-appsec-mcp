"""
Logging setup for the MCP server: stderr plus a rotating file at
``<plugin dir>/logs/server.log``.

stdout is the MCP stdio channel, so no handler here ever writes to it. Every
handler uses ``RedactingFormatter``, which masks URL userinfo (proxy passwords)
and bearer tokens in the fully formatted record, tracebacks included, as a
backstop to call sites never logging secrets in the first place.
"""

import logging
import logging.handlers
import os
import re
import sys
import threading

LOG_MAX_BYTES = 1_000_000
LOG_BACKUP_COUNT = 3
_FORMAT = "%(asctime)s %(levelname)s [%(process)d] %(name)s: %(message)s"

logger = logging.getLogger("appsec-mcp")

_REDACTIONS = (
    # scheme://user:pass@host -> scheme://***@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/\s@]+@"), r"\1***@"),
    # Authorization: Bearer <jwt>
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/\-]+=*"), r"\1***"),
    # "access_token": "...", refresh_token=..., client_secret: ...
    (
        re.compile(
            r"(?i)\b(access_token|refresh_token|id_token|client_secret|device_code)"
            r"(['\"]?\s*[:=]\s*['\"]?)[^\s'\",}&]+"
        ),
        r"\1\2***",
    ),
)


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


def setup_logging(plugin_dir: str, level: int = logging.INFO) -> str | None:
    """Configure root logging to stderr and ``<plugin_dir>/logs/server.log``.

    Returns the log file path, or None if the file handler couldn't be set up
    (the server then runs with stderr logging only).
    """
    root = logging.getLogger()
    root.setLevel(level)
    formatter = RedactingFormatter(_FORMAT)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    root.addHandler(stderr_handler)

    log_path = os.path.join(plugin_dir, "logs", "server.log")
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
    except OSError as e:
        logger.warning("Log file disabled: cannot open %s (%s)", log_path, e)
        return None
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)
    return log_path


def install_exception_hooks() -> None:
    """Route uncaught exceptions (main thread and worker threads) to the log."""

    def _excepthook(exc_type, exc, tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc, tb)
            return
        logger.critical("Unhandled exception", exc_info=(exc_type, exc, tb))

    def _thread_excepthook(args):
        if args.exc_type is SystemExit:
            return
        logger.critical(
            "Unhandled exception in thread %s",
            args.thread.name if args.thread else "?",
            exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
        )

    sys.excepthook = _excepthook
    threading.excepthook = _thread_excepthook
