# SPDX-License-Identifier: BUSL-1.1
# Part of the agentbastion commercial gateway. Licensed under the Business Source
# License 1.1 (see LICENSE-BSL), NOT MIT. Converts to Apache-2.0 on the Change Date.
"""Optional shared store (Redis) behind rate limiting and usage metering, so the
gateway can run as multiple processes / replicas with correct shared counters.

Default is no store: the in-memory rate limiter and single-file usage meter keep
working unchanged. Set AGENTBASTION_REDIS_URL to switch both to Redis.

Security notes:
  - Redis exceptions can embed the connection URL (with password). We NEVER log
    the exception object - only its type name - to avoid leaking credentials.
  - Keys are namespaced (`ab:rl:`, `ab:usage:`) and built from operator-defined
    tenant names, not attacker input.
  - Store errors fail OPEN for rate limiting (availability over strict limiting -
    a Redis outage must not take the gateway down) and are best-effort for usage.
"""

from __future__ import annotations

import logging
import os
from typing import Optional, Protocol

log = logging.getLogger("agentbastion.store")


class Store(Protocol):
    def incr_window(self, key: str, ttl_s: int) -> int: ...
    def hincr(self, name: str, field: str, amount: int = 1) -> None: ...
    def scan_hashes(self, prefix: str) -> dict[str, dict[str, int]]: ...
    # KV ops (used by the key registry, #7)
    def get(self, key: str) -> Optional[str]: ...
    def set(self, key: str, value: str, ttl_s: Optional[int] = None) -> None: ...
    def delete(self, key: str) -> None: ...
    def keys(self, prefix: str) -> list[str]: ...


class RedisStore:
    def __init__(self, url: str) -> None:
        import redis

        self._r = redis.Redis.from_url(url, decode_responses=True)

    def incr_window(self, key: str, ttl_s: int) -> int:
        pipe = self._r.pipeline()
        pipe.incr(key)
        pipe.expire(key, ttl_s)
        count, _ = pipe.execute()
        return int(count)

    def hincr(self, name: str, field: str, amount: int = 1) -> None:
        self._r.hincrby(name, field, amount)

    def scan_hashes(self, prefix: str) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for key in self._r.scan_iter(match=prefix + "*"):
            tenant = key[len(prefix):]
            out[tenant] = {k: int(v) for k, v in self._r.hgetall(key).items()}
        return out

    def get(self, key: str) -> Optional[str]:
        return self._r.get(key)

    def set(self, key: str, value: str, ttl_s: Optional[int] = None) -> None:
        self._r.set(key, value, ex=ttl_s if ttl_s else None)

    def delete(self, key: str) -> None:
        self._r.delete(key)

    def keys(self, prefix: str) -> list[str]:
        return list(self._r.scan_iter(match=prefix + "*"))


def build_store() -> Optional[Store]:
    """RedisStore if AGENTBASTION_REDIS_URL is set and the redis SDK is present,
    else None (in-process defaults). Never raises, never logs the URL."""
    url = os.getenv("AGENTBASTION_REDIS_URL")
    if not url:
        return None
    try:
        return RedisStore(url)
    except Exception as e:  # noqa: BLE001 - type only, never the URL-bearing message
        log.warning("redis store unavailable (%s); using in-process store", type(e).__name__)
        return None
