# agentbastion docs

- **[Threat model](threat-model.md)** — what it stops, what it doesn't, and the
  fail-open/fail-closed posture of every component. Read this first.
- **[Security policy](../SECURITY.md)** — how to report a vulnerability
  (responsible disclosure).
- **[README](../README.md)** — install, quick start, the SDK guards, the drop-in
  Anthropic wrapper, the HTTP gateway (multi-tenant, dashboard, rate limiting,
  alerting, usage, billing, playground), and the benchmark.
- **[LICENSING](../LICENSING.md)** — open-core: MIT core + BSL 1.1 gateway.

## Quick links

| I want to… | See |
|---|---|
| Guard a Python agent | README → Quick start |
| Guard an existing Anthropic app with ~2 lines | README → Drop-in Anthropic wrapper |
| Scan data a tool returns (indirect injection) | README → Scanning tool results |
| Run the guards as a service | README → HTTP gateway |
| Serve multiple tenants with per-key limits/billing | README → Multi-tenant keys, Operations, Billing |
| Measure real catch-rate | README → Benchmark |
| Understand the security guarantees | [Threat model](threat-model.md) |
| Report a vulnerability | [SECURITY.md](../SECURITY.md) |
| Add a signature language | [issue #1](https://github.com/Rinkia/agentbastion/issues/1) |

> A generated docs site (mkdocs-material) can wrap these Markdown files later;
> they're written to stand alone in the meantime.
