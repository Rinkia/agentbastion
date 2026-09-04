# Licensing

agentbastion is **open-core**. Two licenses, by file:

## MIT — the core (free, forever)

Everything except the three files listed below is **MIT** (see [`LICENSE`](LICENSE)).
That includes the whole SDK you `pip install agentbastion` for:

- the guards — `firewall.py`, `inbound.py`, `outbound.py`, `tools.py`, `events.py`
- the drop-in integrations — `integrations.py`
- the benchmark and examples

Use it, fork it, embed it, ship it commercially. No strings.

## BSL 1.1 — the commercial gateway (source-available)

These files are licensed under the **Business Source License 1.1**
(see [`LICENSE-BSL`](LICENSE-BSL)):

- `agentbastion/gateway.py`
- `agentbastion/gateway_ops.py`
- `agentbastion/billing.py`

You can read the source, modify it, and run it in production — **including for
your own company**. The one thing you may **not** do is offer it to third parties
as a hosted or managed service that competes with the agentbastion hosted
offering (multi-tenant gateway, usage metering, billing).

Each of these files **converts to Apache 2.0 on the Change Date (2029-09-04)** —
four years is the ceiling; after it, they're fully open source.

## Why

The guards are the useful, embeddable part — keeping them MIT means anyone can
adopt agentbastion with zero friction. The multi-tenant gateway is the part a
competitor would resell as-a-service; BSL keeps that from happening while still
letting you self-host and read every line. This is the same model Sentry,
HashiCorp, and CockroachDB use.

Need a commercial license for the BSL parts (e.g. to offer a competing service)?
Email rizzellostefano@gmail.com.

*Not legal advice — this file summarizes the licenses; the license texts govern.*
