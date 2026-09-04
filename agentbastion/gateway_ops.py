# SPDX-License-Identifier: BUSL-1.1
# Part of the agentbastion commercial gateway. Licensed under the Business Source
# License 1.1 (see LICENSE-BSL), NOT MIT. Converts to Apache-2.0 on the Change Date.
"""Gateway operational features: rate limiting, block-spike alerting, and usage
metering. Kept out of gateway.py so the routing layer stays readable.

All three are in-memory / single-file and per-process - fine for a v0 gateway.
ponytail: back the rate limiter + usage meter with Redis/Postgres when you run
more than one gateway process.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from typing import Callable, Optional

log = logging.getLogger("agentbastion.gateway")


class RateLimiter:
    """Fixed-window per-tenant limiter. `per_minute <= 0` disables it."""

    def __init__(self, per_minute: int) -> None:
        self.limit = per_minute
        self._win: dict[str, tuple[int, int]] = {}
        self._lock = threading.Lock()

    def allow(self, tenant: str) -> bool:
        if self.limit <= 0:
            return True
        window = int(time.time() // 60)
        with self._lock:
            ws, count = self._win.get(tenant, (window, 0))
            if ws != window:
                ws, count = window, 0
            if count >= self.limit:
                self._win[tenant] = (ws, count)
                return False
            self._win[tenant] = (ws, count + 1)
            return True


class AlertMonitor:
    """Fire an alert when a tenant's blocks in a sliding window cross a threshold.
    Debounced per tenant (one alert per window). `threshold <= 0` disables it."""

    def __init__(self, threshold: int, window_s: int, webhook: Optional[str] = None,
                 sink: Optional[Callable[[dict], None]] = None) -> None:
        self.threshold = threshold
        self.window = window_s
        self.webhook = webhook
        self._blocks: dict[str, deque] = defaultdict(deque)
        self._last_alert: dict[str, float] = {}
        self._lock = threading.Lock()
        self._sink = sink or (lambda m: log.warning("ALERT %s", m))

    def record_block(self, tenant: str, detail: str = "") -> None:
        if self.threshold <= 0:
            return
        now = time.time()
        with self._lock:
            dq = self._blocks[tenant]
            dq.append(now)
            while dq and now - dq[0] > self.window:
                dq.popleft()
            breached = len(dq) >= self.threshold and now - self._last_alert.get(tenant, 0.0) > self.window
            count = len(dq)
            if breached:
                self._last_alert[tenant] = now
        if breached:
            self._fire({"type": "block_spike", "tenant": tenant, "count": count,
                        "window_s": self.window, "last_detail": detail})

    def _fire(self, msg: dict) -> None:
        self._sink(msg)
        if self.webhook:
            try:
                import httpx

                httpx.post(self.webhook, json=msg, timeout=5)
            except Exception as e:  # noqa: BLE001 - alerting must never break the request path
                log.warning("alert webhook failed: %s", e)


class UsageMeter:
    """Durable per-tenant billable counters (checks by kind + blocks), persisted
    write-through to a JSON file so counts survive restarts."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._data = self._load()

    def _load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}

    def record(self, tenant: str, kind: str, blocked: bool = False) -> None:
        with self._lock:
            t = self._data.setdefault(tenant, {"input": 0, "output": 0, "tool": 0, "blocks": 0})
            t[kind] = t.get(kind, 0) + 1
            if blocked:
                t["blocks"] = t.get("blocks", 0) + 1
            self._save()

    def _save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._data, f)
        os.replace(tmp, self.path)  # atomic

    def snapshot(self) -> dict:
        with self._lock:
            return json.loads(json.dumps(self._data))
