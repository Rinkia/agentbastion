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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Protocol

log = logging.getLogger("agentbastion.gateway")


class RateLimiter:
    """Fixed-window per-tenant limiter. `per_minute <= 0` disables it. With a
    shared `store` (Redis) the window is shared across gateway processes; without
    one it is per-process (in-memory)."""

    def __init__(self, per_minute: int, store=None) -> None:
        self.limit = per_minute
        self._store = store
        self._win: dict[str, tuple[int, int]] = {}
        self._lock = threading.Lock()

    def allow(self, tenant: str) -> bool:
        if self.limit <= 0:
            return True
        window = int(time.time() // 60)
        if self._store is not None:
            try:
                key = f"ab:rl:{tenant}:{window}"
                count = self._store.incr_window(key, 120)  # 2-window TTL
                return count <= self.limit
            except Exception as e:  # noqa: BLE001 - fail OPEN; a store outage must not 429 everyone
                log.warning("rate limiter store error (%s); failing open", type(e).__name__)
                return True
        with self._lock:
            ws, count = self._win.get(tenant, (window, 0))
            if ws != window:
                ws, count = window, 0
            if count >= self.limit:
                self._win[tenant] = (ws, count)
                return False
            self._win[tenant] = (ws, count + 1)
            return True


class Channel(Protocol):
    def send(self, alert: dict) -> None: ...


def _fmt(alert: dict) -> str:
    return (f"agentbastion block spike - tenant '{alert['tenant']}': {alert['count']} "
            f"blocks in {alert['window_s']}s ({str(alert.get('last_detail', ''))[:120]})")


class WebhookChannel:
    def __init__(self, url: str) -> None:
        self.url = url

    def send(self, alert: dict) -> None:
        import httpx

        httpx.post(self.url, json=alert, timeout=5)


class SlackChannel:
    def __init__(self, url: str) -> None:
        self.url = url

    def send(self, alert: dict) -> None:
        import httpx

        httpx.post(self.url, json={"text": ":rotating_light: " + _fmt(alert)}, timeout=5)


class PagerDutyChannel:
    def __init__(self, routing_key: str) -> None:
        self.routing_key = routing_key

    def send(self, alert: dict) -> None:
        import httpx

        httpx.post("https://events.pagerduty.com/v2/enqueue", timeout=5, json={
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {"summary": _fmt(alert), "source": "agentbastion",
                        "severity": "warning", "custom_details": alert},
        })


_CHANNEL_TYPES = {"webhook": ("url", WebhookChannel), "slack": ("url", SlackChannel),
                  "pagerduty": ("routing_key", PagerDutyChannel)}


@dataclass
class Rule:
    threshold: int
    window_s: int = 60
    channels: list[str] = field(default_factory=list)


class AlertMonitor:
    """Fire alerts when a tenant's blocks in a sliding window cross a threshold,
    per-tenant rules with a default, dispatched to named channels. Debounced per
    tenant (one alert per window). A rule with threshold <= 0 disables alerting
    for that tenant."""

    def __init__(self, default_rule: Optional[Rule], tenant_rules: dict[str, Rule],
                 channels: dict[str, Channel], sink: Optional[Callable[[dict], None]] = None) -> None:
        self._default = default_rule
        self._tenant_rules = tenant_rules
        self._channels = channels
        self._blocks: dict[str, deque] = defaultdict(deque)
        self._last_alert: dict[str, float] = {}
        self._lock = threading.Lock()
        self._sink = sink or (lambda m: log.warning("ALERT %s", m))

    def _rule_for(self, tenant: str) -> Optional[Rule]:
        return self._tenant_rules.get(tenant) or self._default

    def record_block(self, tenant: str, detail: str = "") -> None:
        rule = self._rule_for(tenant)
        if rule is None or rule.threshold <= 0:
            return
        now = time.time()
        with self._lock:
            dq = self._blocks[tenant]
            dq.append(now)
            while dq and now - dq[0] > rule.window_s:
                dq.popleft()
            breached = len(dq) >= rule.threshold and now - self._last_alert.get(tenant, 0.0) > rule.window_s
            count = len(dq)
            if breached:
                self._last_alert[tenant] = now
        if breached:
            self._fire(rule, {"type": "block_spike", "tenant": tenant, "count": count,
                              "window_s": rule.window_s, "last_detail": detail})

    def _fire(self, rule: Rule, alert: dict) -> None:
        self._sink(alert)
        for name in rule.channels:
            ch = self._channels.get(name)
            if ch is None:
                continue
            try:
                ch.send(alert)
            except Exception as e:  # noqa: BLE001 - alerting must never break the request path;
                # log the error TYPE only - the exception can embed the channel URL / routing key.
                log.warning("alert channel '%s' failed (%s)", name, type(e).__name__)


def _channels_from(cfg: dict) -> dict[str, Channel]:
    out: dict[str, Channel] = {}
    for name, spec in (cfg or {}).items():
        entry = _CHANNEL_TYPES.get((spec or {}).get("type", ""))
        if not entry:
            log.warning("unknown alert channel type for '%s'; skipping", name)
            continue
        arg_name, cls = entry
        value = spec.get(arg_name)
        if value:
            out[name] = cls(value)
    return out


def _rule_from(spec: Optional[dict]) -> Optional[Rule]:
    if not spec:
        return None
    return Rule(int(spec.get("threshold", 0)), int(spec.get("window_s", 60)),
               list(spec.get("channels", []) or []))


def build_alert_monitor(rules_path: Optional[str] = None,
                        sink: Optional[Callable[[dict], None]] = None) -> AlertMonitor:
    """From a rules YAML (AGENTBASTION_ALERT_RULES) if present, else from the
    single-rule env vars (AGENTBASTION_ALERT_THRESHOLD/_WINDOW/_WEBHOOK)."""
    rules_path = rules_path or os.getenv("AGENTBASTION_ALERT_RULES")
    if rules_path:
        import yaml

        data = yaml.safe_load(Path(rules_path).read_text(encoding="utf-8")) or {}
        channels = _channels_from(data.get("channels", {}))
        tenant_rules = {t: r for t, r in ((k, _rule_from(v)) for k, v in (data.get("tenants") or {}).items()) if r}
        return AlertMonitor(_rule_from(data.get("default")), tenant_rules, channels, sink)
    threshold = int(os.getenv("AGENTBASTION_ALERT_THRESHOLD", "0"))
    window = int(os.getenv("AGENTBASTION_ALERT_WINDOW", "60"))
    webhook = os.getenv("AGENTBASTION_ALERT_WEBHOOK")
    channels: dict[str, Channel] = {}
    names: list[str] = []
    if webhook:
        channels["default_webhook"] = WebhookChannel(webhook)
        names = ["default_webhook"]
    default = Rule(threshold, window, names) if threshold > 0 else None
    return AlertMonitor(default, {}, channels, sink)


class UsageMeter:
    """Durable per-tenant billable counters (checks by kind + blocks). With a
    shared `store` (Redis) counters are shared across processes; without one they
    are write-through to a JSON file so counts survive restarts."""

    def __init__(self, path: str, store=None) -> None:
        self.path = path
        self._store = store
        self._lock = threading.Lock()
        self._data = {} if store is not None else self._load()

    def _load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}

    def record(self, tenant: str, kind: str, blocked: bool = False) -> None:
        if self._store is not None:
            try:
                self._store.hincr(f"ab:usage:{tenant}", kind, 1)
                if blocked:
                    self._store.hincr(f"ab:usage:{tenant}", "blocks", 1)
            except Exception as e:  # noqa: BLE001 - best-effort; never break the request
                log.warning("usage store error (%s); usage not recorded for this call", type(e).__name__)
            return
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
        if self._store is not None:
            try:
                return self._store.scan_hashes("ab:usage:")
            except Exception as e:  # noqa: BLE001
                log.warning("usage snapshot store error (%s)", type(e).__name__)
                return {}
        with self._lock:
            return json.loads(json.dumps(self._data))
