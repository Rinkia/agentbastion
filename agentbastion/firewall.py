"""Firewall - orchestrates the three guards and the event log.

    USER / ATTACKER          FIREWALL                     AGENT (LLM + data/tools)
    input           -->  [inbound scan] --block-->
                    -->  ok                      -->      agent runs
    agent action    <--  [tool guard] --block-->  <--     agent wants a tool
    reply           <--  [outbound redact]        <--     agent reply
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Optional

from .events import Event, EventLog
from .inbound import InboundGuard, LLMJudge, ScanResult
from .outbound import PiiRedactor
from .tools import ToolDecision, ToolPolicy


@dataclass(frozen=True)
class Verdict:
    """Result of a guard check. Immutable."""

    allowed: bool
    stage: str
    reason: str
    matches: tuple[str, ...] = ()


class BlockedError(Exception):
    def __init__(self, verdict: Verdict) -> None:
        self.verdict = verdict
        super().__init__(f"[{verdict.stage}] blocked: {verdict.reason}")


@dataclass
class Firewall:
    inbound: InboundGuard = field(default_factory=InboundGuard)
    outbound: PiiRedactor = field(default_factory=PiiRedactor)
    tool_policy: Optional[ToolPolicy] = None
    log: EventLog = field(default_factory=EventLog)

    @classmethod
    def with_judge(cls, client, model: str = "claude-haiku-4-5", **kwargs) -> "Firewall":
        """Build a Firewall whose inbound guard also uses the Anthropic LLM judge."""
        inbound = InboundGuard(judge=LLMJudge(client, model=model))
        return cls(inbound=inbound, **kwargs)

    # --- inbound -----------------------------------------------------------
    def check_input(self, text: str, tenant: Optional[str] = None) -> Verdict:
        result: ScanResult = self.inbound.scan(text)
        blocked = self.inbound.is_blocked(result)
        reason = _inbound_reason(result)
        verdict = Verdict(
            allowed=not blocked,
            stage="inbound",
            reason=reason,
            matches=result.matches,
        )
        self.log.log(Event(
            stage="inbound",
            decision="block" if blocked else "allow",
            detail=reason,
            extra={"matches": list(result.matches), "judge_flagged": result.judge_flagged, "tenant": tenant},
        ))
        return verdict

    # --- tool result (indirect / data-borne injection) --------------------
    def check_tool_result(self, text: str, tenant: Optional[str] = None) -> Verdict:
        """Scan the DATA a tool returns (RAG chunk, fetched page, API payload)
        before the agent sees it. Indirect injection lives here - a poisoned
        document telling the agent to ignore the user or exfiltrate data. Same
        inbound scanner, distinct stage so it's attributable in the log."""
        result: ScanResult = self.inbound.scan(text)
        blocked = self.inbound.is_blocked(result)
        reason = _inbound_reason(result)
        self.log.log(Event(
            stage="tool_result",
            decision="block" if blocked else "allow",
            detail=reason,
            extra={"matches": list(result.matches), "judge_flagged": result.judge_flagged, "tenant": tenant},
        ))
        return Verdict(allowed=not blocked, stage="tool_result", reason=reason, matches=result.matches)

    # --- tool --------------------------------------------------------------
    def check_tool(self, tool: str, tool_input: Any = None, tenant: Optional[str] = None) -> Verdict:
        if self.tool_policy is None:
            return Verdict(True, "tool", "no policy configured")
        decision: ToolDecision = self.tool_policy.check(tool, tool_input)
        if decision.allowed:
            self.tool_policy.record(tool)
        self.log.log(Event(
            stage="tool",
            decision="allow" if decision.allowed else "block",
            detail=f"{tool}: {decision.reason}",
            extra={"tenant": tenant},
        ))
        return Verdict(decision.allowed, "tool", decision.reason, matches=(tool,))

    # --- outbound ----------------------------------------------------------
    def check_output(self, text: str, tenant: Optional[str] = None) -> tuple[str, Verdict]:
        redacted, findings = self.outbound.redact(text)
        kinds = tuple(f.kind for f in findings)
        if findings:
            self.log.log(Event(
                stage="outbound",
                decision="redact",
                detail=f"redacted {len(findings)}",
                extra={"kinds": list(kinds), "tenant": tenant},
            ))
        verdict = Verdict(
            allowed=True,  # outbound redacts rather than blocks
            stage="outbound",
            reason=f"redacted {len(findings)} item(s)" if findings else "clean",
            matches=kinds,
        )
        return redacted, verdict


def _inbound_reason(result: ScanResult) -> str:
    parts = []
    if result.matches:
        parts.append("signatures=" + ",".join(result.matches))
    if result.judge_flagged:
        parts.append(f"judge={result.judge_reason or 'flagged'}")
    return "; ".join(parts) if parts else "clean"


def guard(
    firewall: Optional[Firewall] = None,
    *,
    block_injection: bool = True,
    redact_pii: bool = True,
    on_block: str = "raise",  # raise | return
) -> Callable:
    """Decorate an agent function `fn(user_input: str) -> str`.

    Runs the inbound guard on the input and the outbound redactor on the reply.
    Tool-call guarding is enforced inside the agent's tool executor via
    `firewall.check_tool(...)` - see examples/basic_agent.py.

        @guard()
        def my_agent(user_input: str) -> str:
            ...

    on_block="raise" -> raises BlockedError. on_block="return" -> returns a
    safe refusal string instead (better UX for a chat surface).
    """
    fw = firewall or Firewall()

    def decorator(fn: Callable[[str], str]) -> Callable[[str], str]:
        @wraps(fn)
        def wrapper(user_input: str, *args, **kwargs) -> str:
            if block_injection:
                verdict = fw.check_input(user_input)
                if not verdict.allowed:
                    if on_block == "return":
                        return "Request blocked: it looks like a prompt-injection attempt."
                    raise BlockedError(verdict)

            reply = fn(user_input, *args, **kwargs)

            if redact_pii and isinstance(reply, str):
                reply, _ = fw.check_output(reply)
            return reply

        return wrapper

    return decorator
