"""Tool guard - the differentiator. Everyone scans prompts; few guard what the
agent actually DOES. This is where the real damage lives (mass email, delete,
external calls, exfil).

Policy is a small YAML file:

    default: deny            # deny | allow  (default when a call matches nothing)
    allow:                   # tool names the agent may call
      - get_ticket
      - search_docs
    deny:                    # explicit block (wins over allow)
      - delete_database
    rate_limits:             # optional max calls per tool this session
      send_email: 3

Decision order: deny-list -> allow-list -> default -> rate limit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ToolDecision:
    allowed: bool
    reason: str


class ToolBlocked(Exception):
    def __init__(self, tool: str, decision: ToolDecision) -> None:
        self.tool = tool
        self.decision = decision
        super().__init__(f"tool '{tool}' blocked: {decision.reason}")


@dataclass
class ToolPolicy:
    default: str = "deny"  # deny | allow
    allow: frozenset[str] = frozenset()
    deny: frozenset[str] = frozenset()
    rate_limits: dict[str, int] = field(default_factory=dict)
    # Per-session call counters. Stateful by nature (a guard's own bookkeeping,
    # not caller data), so mutation here is fine.
    _counts: dict[str, int] = field(default_factory=dict, repr=False)

    def check(self, tool: str, tool_input: Any = None) -> ToolDecision:
        if tool in self.deny:
            return ToolDecision(False, "on deny-list")
        if self.allow and tool not in self.allow:
            return ToolDecision(False, "not on allow-list")
        if not self.allow and self.default == "deny":
            return ToolDecision(False, "default-deny and no allow-list match")

        limit = self.rate_limits.get(tool)
        if limit is not None:
            used = self._counts.get(tool, 0)
            if used >= limit:
                return ToolDecision(False, f"rate limit reached ({limit})")

        return ToolDecision(True, "allowed")

    def record(self, tool: str) -> None:
        """Call after a tool actually runs, so rate limits count real executions."""
        self._counts[tool] = self._counts.get(tool, 0) + 1

    def enforce(self, tool: str, tool_input: Any = None) -> ToolDecision:
        """Check, raise ToolBlocked if denied, else record the call and return."""
        decision = self.check(tool, tool_input)
        if not decision.allowed:
            raise ToolBlocked(tool, decision)
        self.record(tool)
        return decision


def load_policy(path: str | Path) -> ToolPolicy:
    import yaml

    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return ToolPolicy(
        default=str(data.get("default", "deny")).lower(),
        allow=frozenset(data.get("allow", []) or []),
        deny=frozenset(data.get("deny", []) or []),
        rate_limits=dict(data.get("rate_limits", {}) or {}),
    )
