"""Tests for single_flight.py — the credential-resolution coalescer.

These exercise the mechanism directly; test_auth.py covers the two providers
that use it.
"""

import os
import sys
import threading
import time

import pytest

# Add plugin dir to path so we can import single_flight
_plugin_dir = os.path.join(os.path.dirname(__file__), "..", "..")
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from single_flight import SingleFlight  # noqa: E402


def _run_together(fn, n=8):
    """Call ``fn`` on ``n`` threads released from a barrier; return results."""
    barrier = threading.Barrier(n)
    results: list[object] = [None] * n

    def worker(i):
        barrier.wait(timeout=10)
        try:
            results[i] = ("ok", fn())
        except BaseException as e:  # noqa: BLE001
            results[i] = ("err", str(e))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
        assert not t.is_alive(), "worker thread did not finish — deadlock?"
    return results


class TestCoalescing:
    def test_one_resolve_for_a_batch(self):
        sf = SingleFlight()
        state = {"token": None}
        calls = []

        def ready():
            return state["token"]

        def resolve():
            calls.append(1)
            time.sleep(0.05)
            state["token"] = "tok"
            return "tok"

        results = _run_together(lambda: sf.run(ready, resolve))

        assert len(calls) == 1
        assert results == [("ok", "tok")] * 8

    def test_ready_short_circuits_without_resolving(self):
        sf = SingleFlight()

        def resolve():
            raise AssertionError("resolve must not be called when ready() answers")

        assert sf.run(lambda: "cached", resolve) == "cached"

    def test_waiters_share_one_failure(self):
        sf = SingleFlight()
        calls = []

        def resolve():
            calls.append(1)
            time.sleep(0.05)
            raise RuntimeError("HTTP 429")

        results = _run_together(lambda: sf.run(lambda: None, resolve))

        assert len(calls) == 1, f"a rejected attempt was replayed {len(calls)} times"
        assert results == [("err", "HTTP 429")] * 8

    def test_failure_is_not_sticky_for_later_callers(self):
        # A caller arriving after the attempt finished must get its own try —
        # otherwise one transient 429 would disable auth for the process.
        sf = SingleFlight()
        with pytest.raises(RuntimeError, match="boom"):
            sf.run(lambda: None, lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        assert sf.run(lambda: None, lambda: "tok") == "tok"

    def test_clear_error_drops_a_shared_failure(self):
        sf = SingleFlight()
        with pytest.raises(RuntimeError):
            sf.run(lambda: None, lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        sf.clear_error()
        assert sf.run(lambda: None, lambda: "tok") == "tok"

    def test_lock_is_free_while_resolve_runs(self):
        # invalidate()/status() take this lock. If it were held across the
        # network call, a 401 handler would block for the length of an HTTP
        # request (or a whole interactive browser login).
        sf = SingleFlight()
        acquired = threading.Event()
        entered = threading.Event()

        def resolve():
            entered.set()
            time.sleep(0.3)
            return "tok"

        def observer():
            entered.wait(timeout=5)
            with sf.lock:
                acquired.set()

        t = threading.Thread(target=observer)
        t.start()
        sf.run(lambda: None, resolve)
        t.join(timeout=5)

        assert acquired.is_set(), "the state lock was held for the whole resolve"

    def test_second_batch_resolves_again(self):
        sf = SingleFlight()
        calls = []

        def resolve():
            calls.append(1)
            time.sleep(0.02)
            return "tok"

        _run_together(lambda: sf.run(lambda: None, resolve), n=4)
        _run_together(lambda: sf.run(lambda: None, resolve), n=4)

        # ready() never answers here, so each batch must resolve exactly once.
        assert len(calls) == 2, f"expected one resolve per batch, got {len(calls)}"
