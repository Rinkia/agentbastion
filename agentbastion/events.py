"""Event log - every decision the firewall makes, appended as JSONL. This is the
audit trail: what came in, what the agent tried to do, what got blocked/redacted.

`dashboard(path)` reads the log and prints a summary. v0 is a CLI table - a
hosted dashboard is the paid tier later.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Event:
    stage: str        # inbound | tool | outbound
    decision: str     # allow | block | redact
    detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=_now)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


class EventLog:
    """Append-only JSONL sink. Pass path=None to disable logging (no-op).

    Optional `redactor` (any object with `.redact(text) -> (redacted, findings)`)
    scrubs PII from the event `detail` before it is written, so the audit trail
    doesn't itself become a store of sensitive data (a compliance concern, #12)."""

    def __init__(self, path: Optional[str | Path] = "agentbastion.jsonl", redactor=None) -> None:
        self._path = Path(path) if path is not None else None
        self._redactor = redactor

    def log(self, event: Event) -> None:
        if self._path is None:
            return
        if self._redactor is not None and event.detail:
            try:
                event = replace(event, detail=self._redactor.redact(event.detail)[0])
            except Exception:  # noqa: BLE001 - logging must never break the request
                pass
        with self._path.open("a", encoding="utf-8") as f:
            f.write(event.to_json() + "\n")


def _iter_events(path: Path):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def export_events(path: str | Path, since: Optional[str] = None, until: Optional[str] = None,
                  tenant: Optional[str] = None, fmt: str = "jsonl") -> str:
    """Filtered audit export for compliance (#12). `since`/`until` are ISO-8601
    UTC strings (lexicographic compare works for that format); `tenant` filters
    by the logged tenant; `fmt` is 'jsonl' or 'csv'."""
    rows = []
    for e in _iter_events(Path(path)):
        ts = e.get("ts", "")
        if since and ts < since:
            continue
        if until and ts > until:
            continue
        if tenant and (e.get("extra") or {}).get("tenant") != tenant:
            continue
        rows.append(e)
    if fmt == "csv":
        import csv
        import io

        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["ts", "stage", "decision", "tenant", "detail"])
        for e in rows:
            w.writerow([e.get("ts", ""), e.get("stage", ""), e.get("decision", ""),
                        (e.get("extra") or {}).get("tenant", ""), e.get("detail", "")])
        return buf.getvalue()
    return "\n".join(json.dumps(e, ensure_ascii=False) for e in rows)


def prune_events(path: str | Path, older_than_days: int) -> int:
    """Retention: drop events older than `older_than_days`, rewrite atomically.
    Returns the number removed."""
    p = Path(path)
    if not p.exists() or older_than_days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
    kept, removed = [], 0
    for e in _iter_events(p):
        ts = e.get("ts", "")
        try:
            keep = datetime.fromisoformat(ts) >= cutoff
        except (ValueError, TypeError):
            keep = True  # unparseable timestamp -> keep (don't lose data)
        if keep:
            kept.append(e)
        else:
            removed += 1
    tmp = str(p) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for e in kept:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    os.replace(tmp, p)  # atomic
    return removed


def dashboard(path: str | Path = "agentbastion.jsonl") -> str:
    """Read the log and return a printable summary."""
    p = Path(path)
    if not p.exists():
        return f"No log at {p}"

    stages: Counter[str] = Counter()
    decisions: Counter[str] = Counter()
    blocks: Counter[str] = Counter()
    total = 0
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        e = json.loads(line)
        total += 1
        stages[e.get("stage", "?")] += 1
        decisions[e.get("decision", "?")] += 1
        if e.get("decision") == "block":
            blocks[f"{e.get('stage')}: {e.get('detail')}"] += 1

    lines = [
        f"agentbastion - {total} events from {p}",
        "-" * 48,
        "By stage:    " + ", ".join(f"{k}={v}" for k, v in stages.most_common()),
        "By decision: " + ", ".join(f"{k}={v}" for k, v in decisions.most_common()),
    ]
    if blocks:
        lines.append("Top blocks:")
        for reason, n in blocks.most_common(10):
            lines.append(f"  {n:>4}  {reason}")
    return "\n".join(lines)


def stats(path: str | Path = "agentbastion.jsonl") -> dict:
    """Aggregate the audit log per tenant, for the dashboard / stats endpoint.

    Returns {"total": int, "tenants": {name: {events, by_stage, by_decision,
    blocks, recent_blocks}}}. Reads the whole file (v0 - fine for modest logs;
    a real deployment would roll the log or back it with a store)."""
    p = Path(path)
    out: dict = {"total": 0, "tenants": {}}
    if not p.exists():
        return out

    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        out["total"] += 1
        tenant = (e.get("extra") or {}).get("tenant") or "default"
        t = out["tenants"].setdefault(
            tenant,
            {"events": 0, "by_stage": {}, "by_decision": {}, "blocks": 0, "recent_blocks": []},
        )
        t["events"] += 1
        stage, decision = e.get("stage", "?"), e.get("decision", "?")
        t["by_stage"][stage] = t["by_stage"].get(stage, 0) + 1
        t["by_decision"][decision] = t["by_decision"].get(decision, 0) + 1
        if decision == "block":
            t["blocks"] += 1
            t["recent_blocks"].append({"ts": e.get("ts"), "stage": stage, "detail": e.get("detail", "")})

    for t in out["tenants"].values():
        t["recent_blocks"] = t["recent_blocks"][-20:][::-1]  # newest first, cap 20
    return out


if __name__ == "__main__":
    import sys

    print(dashboard(sys.argv[1] if len(sys.argv) > 1 else "agentbastion.jsonl"))
