# agentbastion

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
pip install agentbastion            # core guards (offline, no model needed)
pip install "agentbastion[judge]"   # + Anthropic LLM judge for subtle injection
```

## Quick start

```python
from agentbastion import Firewall, guard, load_policy

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

Every decision is appended to `agentbastion.jsonl`. Summarize it:

```bash
python -m agentbastion.events agentbastion.jsonl
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

## Benchmark

The inbound guard's catch-rate is measured, not assumed. A labeled corpus
([`benchmark/corpus.jsonl`](benchmark/corpus.jsonl)) mixes injection, exfiltration,
jailbreak-persona, delimiter, obfuscation, instruction-override, and indirect
attacks with benign business messages — including trap benigns that carry
trigger words in innocent context ("please ignore my previous email").

```bash
python benchmark/eval.py     # confusion matrix, precision/recall/F1, per-category recall, misses + FPs
```

`tests/test_corpus.py` gates recall and false-positive rate in CI, so a
signature change that regresses coverage fails the build. The corpus is small
and self-authored — it proves coverage of known attack *shapes*, not a
real-world catch-rate. The optional LLM judge lifts recall on the subtle
residual the heuristics miss.

## Tests

```bash
pip install "agentbastion[dev]"
pytest -q
```

MIT.
