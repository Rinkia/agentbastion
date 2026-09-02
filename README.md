# agentaegis

A checkpoint between the AI agent your business ships and the world. Businesses
now deploy chatbots, copilots, and agents wired to their data and tools — and
almost nobody secures that new surface. This does.

**Three guards, one product:**

```
  USER / ATTACKER          FIREWALL                     AGENT (LLM + data/tools)
  input           -->  [1 inbound scan] --block-->
                  -->  ok                          -->  agent runs
  agent action    <--  [2 tool guard]  --block-->  <--  agent wants a tool
  reply           <--  [3 outbound redact]         <--  agent reply
```

1. **Inbound** — block prompt injection / jailbreaks before the model sees them.
2. **Tool** — stop the agent doing something dangerous (mass email, delete, refund, exfil). *This is the differentiator — everyone scans prompts; few guard what the agent actually does.*
3. **Outbound** — redact PII and secrets from the reply.

Ships as a drop-in SDK: your data never leaves your box. A hosted gateway with
dashboards and alerts is the paid tier later.

## Install

```bash
pip install agentaegis            # core guards (offline, no model needed)
pip install "agentaegis[judge]"   # + Anthropic LLM judge for subtle injection
```

## Quick start

```python
from agentaegis import Firewall, guard, load_policy

firewall = Firewall()                                  # heuristics + PII redaction
firewall.tool_policy = load_policy("allowlist.yaml")   # gate tool calls

@guard(firewall)                    # inbound + outbound guards
def my_agent(user_input: str) -> str:
    ...                             # your agent; call firewall.check_tool() in its tool loop
    return reply
```

Full working agent on the raw Anthropic SDK (all three guards): [`examples/basic_agent.py`](examples/basic_agent.py).

### Tool policy (`allowlist.yaml`)

```yaml
default: deny
allow: [get_order_status, search_faq]
deny:  [issue_refund]        # money movement stays human-approved
rate_limits: { get_order_status: 5 }
```

Decision order: deny → allow → default → rate limit.

### Optional LLM judge

```python
import anthropic
firewall = Firewall.with_judge(anthropic.Anthropic())   # runs on claude-haiku-4-5
```

Heuristics are free and offline. The judge catches subtler attempts at real
per-request cost/latency — turn it on for sensitive routes, off for high-volume
low-risk ones. It **fails open**: a judge outage never takes your agent down.

### Audit log

Every decision is appended to `agentaegis.jsonl`. Summarize it:

```bash
python -m agentaegis.events agentaegis.jsonl
```

## What this is not

**Defense in depth, not a silver bullet.** No injection detector is perfect and
no PII regex catches everything. Run this as one layer alongside least-privilege
tool scoping, human approval on money movement, and real monitoring. Build like
it will be attacked — because a security tool will be.

Known v0 ceilings (all have an upgrade path in the code):
- **Injection** = hand-rolled regex signatures + optional LLM judge. Swap in Llama Guard / Rebuff / a fine-tune behind the same interface.
- **PII** = regex for the leaks that cost money (SSN, credit card w/ Luhn, API keys, private keys, email). Swap in Microsoft Presidio for names/addresses/locale-aware NER.
- **Rate limits** = in-memory per process. Move to Redis for multi-worker deployments.

## Tests

```bash
pip install "agentaegis[dev]"
pytest -q
```

MIT.
