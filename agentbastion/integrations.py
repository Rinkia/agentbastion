"""Drop-in integrations so guarding an existing app is a few lines.

Provider-agnostic helpers work on the standard `[{"role","content"}]` message
shape. `GuardedAnthropic` wraps an `anthropic.Anthropic` client so the inbound
guard runs on the last user message and the outbound redactor runs on the
reply, with no other code changes.

    from anthropic import Anthropic
    from agentbastion import Firewall
    from agentbastion.integrations import GuardedAnthropic

    client = GuardedAnthropic(Anthropic(), Firewall())
    client.messages.create(model="claude-opus-5", max_tokens=512,
                           messages=[{"role": "user", "content": "..."}])
"""

from __future__ import annotations

from typing import Any, Optional

from .firewall import BlockedError, Firewall, Verdict


def last_user_text(messages: list[dict]) -> str:
    """Extract the text of the last user message. Handles both a plain string
    content and the block-list form ([{"type":"text","text":...}, ...])."""
    for msg in reversed(messages):
        if msg.get("role") != "user":
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return " ".join(
                b.get("text", "") for b in content
                if isinstance(b, dict) and b.get("type") == "text"
            )
    return ""


def scan_messages(firewall: Firewall, messages: list[dict], tenant: Optional[str] = None) -> Verdict:
    """Run the inbound guard on the last user message of any provider's history."""
    return firewall.check_input(last_user_text(messages), tenant=tenant)


def redact_text(firewall: Firewall, text: str) -> str:
    redacted, _ = firewall.check_output(text)
    return redacted


class _GuardedMessages:
    def __init__(self, inner: Any, firewall: Firewall, tenant: Optional[str]) -> None:
        self._inner = inner
        self._fw = firewall
        self._tenant = tenant

    def create(self, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", []) or []
        verdict = scan_messages(self._fw, messages, tenant=self._tenant)
        if not verdict.allowed:
            raise BlockedError(verdict)  # caller catches to serve a refusal

        resp = self._inner.create(**kwargs)
        # Best-effort outbound redaction of text blocks; never break the call.
        try:
            for block in getattr(resp, "content", []) or []:
                if getattr(block, "type", None) == "text" and isinstance(getattr(block, "text", None), str):
                    block.text = redact_text(self._fw, block.text)
        except Exception:  # noqa: BLE001
            pass
        return resp

    def __getattr__(self, name: str) -> Any:
        # Pass through everything else (stream, count_tokens, ...).
        return getattr(self._inner, name)


class GuardedAnthropic:
    """Wrap an anthropic.Anthropic client. `.messages.create(...)` gains inbound
    + outbound guarding; every other attribute passes through untouched. An
    injected input raises BlockedError - catch it to serve a refusal."""

    def __init__(self, client: Any, firewall: Optional[Firewall] = None, *,
                 tenant: Optional[str] = None) -> None:
        self._client = client
        self._fw = firewall or Firewall()
        self.messages = _GuardedMessages(client.messages, self._fw, tenant)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)
