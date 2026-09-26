"""Coalesce concurrent credential resolutions into a single attempt.

Both auth providers are reached from several threads at once: the MCP SDK
starts each incoming request as its own task
(``mcp/server/lowlevel/server.py``: ``tg.start_soon(self._handle_message, ...)``)
and ``server._run_scan`` hands the blocking HTTP call to
``asyncio.to_thread``, so N in-flight scans mean N threads inside
``get_header()``.

Unsynchronized, each of those threads runs the full credential flow:

* ``JWTAuth`` -- N POSTs to ``/auth/token``. Measured live: 8 threads produced
  8 exchanges and 8 distinct tokens; at 24 threads the endpoint rate-limited
  23 of them and one scan batch lost 23 of its 24 files to
  ``Authentication failed: HTTP 429``.
* ``SharedCacheAuth`` -- N replays of a *rotated* refresh token, which the
  server's reuse detection reads as theft and answers by revoking the whole
  token family; or, on an empty cache, N concurrent RFC 8628 device flows,
  i.e. N browser windows and N codes for one scan.

``SingleFlight`` gives those threads one attempt and one outcome -- the same
credential on success, the same error on failure. Sharing the failure is the
half that is easy to leave out: the failure that matters here is HTTP 429, and
replaying a rejected request N times is the worst available response to being
rate limited. A caller arriving *after* an attempt has finished gets a fresh
attempt, so a transient failure stays retryable.
"""

from __future__ import annotations

import threading
from collections.abc import Callable

__all__ = ["SingleFlight"]


class SingleFlight:
    """One in-flight resolution at a time, with its outcome shared.

    ``lock`` is also the provider's state lock -- hold it when reading or
    mutating the token fields ``resolve`` writes. It is *not* held while
    ``resolve`` runs, so a concurrent ``invalidate()`` never blocks on the
    network.
    """

    def __init__(self) -> None:
        self._cv = threading.Condition()
        self._running = False
        # Outcome of the most recently completed attempt, read only by the
        # threads that waited on it (i.e. the ones notify_all woke).
        self._result: str | None = None
        self._error: str | None = None

    @property
    def lock(self) -> threading.Condition:
        """The provider state lock (a ``Condition``; use as a context manager)."""
        return self._cv

    def clear_error(self) -> None:
        """Forget the last outcome so the next caller attempts again."""
        with self._cv:
            self._result = None
            self._error = None

    def run(self, ready: Callable[[], str | None], resolve: Callable[[], str]) -> str:
        """Return a credential, running ``resolve`` at most once per batch.

        ``ready`` is called under the lock and returns an already-usable
        credential, or None when one must be resolved. ``resolve`` is called by
        exactly one thread per batch, with the lock released.
        """
        with self._cv:
            waited = False
            while self._running:
                self._cv.wait()
                waited = True
            usable = ready()
            if usable is not None:
                return usable
            if waited:
                # An attempt ran while we waited: take its outcome rather than
                # sending the same request again. (``ready`` above usually
                # already answered — a provider that caches what ``resolve``
                # produced sees it there.)
                if self._result is not None:
                    return self._result
                if self._error is not None:
                    raise RuntimeError(self._error)
            self._running = True
            self._result = None
            self._error = None

        result: str | None = None
        error: str | None = None
        try:
            result = resolve()
            return result
        except BaseException as e:  # noqa: BLE001 - recorded, then re-raised
            error = str(e) or type(e).__name__
            raise
        finally:
            with self._cv:
                self._running = False
                self._result = result
                self._error = error
                self._cv.notify_all()
