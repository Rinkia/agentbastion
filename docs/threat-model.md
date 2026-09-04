# Threat model

An honest map of what agentbastion stops, what it does **not**, and the failure
posture of each component. A security tool that oversells itself is worse than
none — read this before you rely on it.

## What it defends

agentbastion sits between the AI agent your business ships and the world, with
three guards:

| Guard | Threat | Mechanism |
|---|---|---|
| **Inbound** | Prompt injection / jailbreaks in user input | Regex signatures (EN/DE/FR/ES/IT) + optional LLM judge + optional model/semantic detectors |
| **Tool** | The agent doing something dangerous (mass email, delete, refund, exfil) | Allow/deny policy + per-tool rate limits, **default-deny** |
| **Tool result** | Indirect injection inside data a tool returns (poisoned RAG chunk / web page) | Same inbound scanner applied to tool output |
| **Outbound** | PII / secret leakage in the reply | Regex (SSN, card, keys, email) or optional Presidio NER |

## What it does NOT stop

- **Every injection.** The heuristics are a high-precision pre-filter; the LLM
  judge catches more but not all; semantic/model detectors help but have a
  threshold. A sufficiently novel or obfuscated attack can pass. This is why it
  is **defense in depth**, layered with least-privilege tools and human review —
  not a silver bullet.
- **The model's own behavior.** Hallucinations, bad reasoning, or unsafe output
  the model produces without an injection are out of scope.
- **Data already inside the model** (training data, fine-tune leakage).
- **Operator misconfiguration** — no-auth mode in production, admin endpoints
  without TLS, over-broad tool allow-lists, plaintext keys in a world-readable
  file.
- **Supply chain** — compromise of your dependencies or the host.

## Trust boundaries & failure posture

The posture is chosen per component, on purpose:

| Component | On failure | Why |
|---|---|---|
| Inbound heuristics | always run (offline) | free, no dependency |
| LLM judge | **fail-open** to heuristics (timeout/error) | a judge outage must not take the agent down; heuristics still run |
| Model / semantic detectors | **fail-soft** (no match) | scanner/embedder outage reduces coverage, never breaks the request |
| Tool policy | **fail-closed** (default-deny) | the dangerous path is denied unless explicitly allowed |
| Gateway auth | **fail-closed** (503 with no keys) | never serve unauthenticated by accident |
| Rate limiter (shared store) | **fail-open** (allow) | a Redis outage must not 429 everyone; availability over strict limiting |
| Usage / billing / alerting | **fail-soft** | metering/alerting must never break a request |
| Verdict cache | bounded LRU | a flood of distinct inputs can't exhaust memory |

The trade-off worth naming: detection layers fail **open** (availability), the
authorization layer fails **closed** (safety). A judge/scanner outage during an
attack means heuristics-only coverage for that window.

## Deployment guidance

- Serve the gateway and especially the admin + key-management endpoints over
  **TLS** (create/rotate responses carry the new key).
- Store keys as secrets; prefer hashed-at-rest keys in the keys file.
- Keep tool allow-lists minimal; keep money movement human-approved.
- Turn the **judge on** for routes you actually care about — heuristics alone
  catch only blatant attacks (see the honest benchmark in the README).
- Enable `AGENTBASTION_LOG_REDACT=1` if the audit log must not hold PII.
