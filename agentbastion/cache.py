"""A small thread-safe TTL + LRU cache, used to memoize inbound scan verdicts so
repeated identical inputs skip the (slow, paid) LLM judge.

Bounded size (LRU eviction) so a flood of distinct inputs can't grow memory
without limit - that bound is a deliberate DoS guard, not just tidiness.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Optional


class TTLCache:
    def __init__(self, maxsize: int = 1024, ttl_s: int = 300) -> None:
        self.maxsize = max(1, maxsize)
        self.ttl = ttl_s
        self._d: "OrderedDict[str, tuple[float, Any]]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            item = self._d.get(key)
            if item is None:
                return None
            ts, val = item
            if self.ttl and time.time() - ts > self.ttl:
                del self._d[key]
                return None
            self._d.move_to_end(key)
            return val

    def set(self, key: str, val: Any) -> None:
        with self._lock:
            self._d[key] = (time.time(), val)
            self._d.move_to_end(key)
            while len(self._d) > self.maxsize:
                self._d.popitem(last=False)  # evict least-recently-used

    def __len__(self) -> int:
        return len(self._d)
