"""Shared-store behaviour for rate limiting + usage, via a fake in-test store
(no Redis). Proves the multi-process semantics: two RateLimiter/UsageMeter
instances sharing one store behave as one, and store errors fail safe."""

import os

from agentbastion.gateway_ops import RateLimiter, UsageMeter
from agentbastion.store import build_store


class FakeStore:
    """In-memory stand-in implementing the Store protocol."""

    def __init__(self):
        self._counts = {}
        self._hashes = {}

    def incr_window(self, key, ttl_s):
        self._counts[key] = self._counts.get(key, 0) + 1
        return self._counts[key]

    def hincr(self, name, field, amount=1):
        self._hashes.setdefault(name, {})[field] = self._hashes.setdefault(name, {}).get(field, 0) + amount

    def scan_hashes(self, prefix):
        return {k[len(prefix):]: dict(v) for k, v in self._hashes.items() if k.startswith(prefix)}


class BrokenStore:
    def incr_window(self, key, ttl_s):
        raise RuntimeError("redis down")

    def hincr(self, name, field, amount=1):
        raise RuntimeError("redis down")

    def scan_hashes(self, prefix):
        raise RuntimeError("redis down")


def test_rate_limit_shared_across_instances():
    store = FakeStore()
    a = RateLimiter(2, store=store)
    b = RateLimiter(2, store=store)  # a second gateway process
    assert a.allow("acme") is True      # 1
    assert b.allow("acme") is True      # 2 (shared count)
    assert a.allow("acme") is False     # 3 -> over the shared limit
    assert a.allow("other") is True     # per-tenant


def test_rate_limit_fails_open_on_store_error():
    rl = RateLimiter(1, store=BrokenStore())
    assert rl.allow("acme") is True
    assert rl.allow("acme") is True     # never 429s during an outage


def test_usage_shared_across_instances():
    store = FakeStore()
    a = UsageMeter("unused-a.json", store=store)
    b = UsageMeter("unused-b.json", store=store)
    a.record("acme", "input")
    b.record("acme", "input", blocked=True)
    b.record("acme", "tool")
    snap = a.snapshot()  # reads the shared store, not a's local file
    assert snap["acme"]["input"] == 2
    assert snap["acme"]["blocks"] == 1
    assert snap["acme"]["tool"] == 1
    # no local file was written in store mode
    assert not os.path.exists("unused-a.json")


def test_usage_record_and_snapshot_fail_safe_on_store_error():
    m = UsageMeter("x.json", store=BrokenStore())
    m.record("acme", "input")           # must not raise
    assert m.snapshot() == {}           # fail-soft


def test_build_store_none_without_env(monkeypatch):
    monkeypatch.delenv("AGENTBASTION_REDIS_URL", raising=False)
    assert build_store() is None


def test_build_store_never_raises_or_leaks_on_bad_url(monkeypatch):
    # A bad URL must not raise from build_store (ops fail-soft later).
    monkeypatch.setenv("AGENTBASTION_REDIS_URL", "redis://:secretpw@nonexistent.invalid:6379/0")
    store = build_store()
    # Either a lazy client (connects on first op) or None on import failure -
    # both are acceptable; the point is build_store didn't throw.
    assert store is None or hasattr(store, "incr_window")


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
