# Security Policy

agentbastion is a security tool, so we take vulnerabilities in it seriously.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Email **rizzellostefano@gmail.com** with:

- a description of the issue and its impact,
- steps to reproduce (a minimal proof-of-concept helps),
- the affected version (`pip show agentbastion`) and component (SDK guard, gateway, etc.).

You can expect an acknowledgement within a few days. We'll work with you on a fix
and coordinate disclosure once a patched release is available.

## Scope

In scope:

- Bypasses of the inbound / tool / outbound guards that defeat their stated
  guarantees (e.g. an injection the default English signatures should catch but
  don't, a tool-policy escape, a PII leak past the redactor).
- Gateway auth issues: key bypass, privilege escalation, tenant isolation
  failure, admin-endpoint exposure.
- Secret leakage (keys/URLs in logs or responses), SSRF, injection into the
  store/log.

Out of scope (by design — see [`docs/threat-model.md`](docs/threat-model.md)):

- Novel prompt-injection phrasings the heuristics don't match **and** the LLM
  judge isn't enabled to catch — the guards are defense in depth, not a
  guarantee. Missed detections are welcome as improvement issues, not
  vulnerabilities, unless they defeat a stated guarantee.
- Operator misconfiguration (running with `AGENTBASTION_ALLOW_NO_AUTH=1` in
  production, exposing admin endpoints without TLS, etc.).

## Safe harbor

We will not pursue or support legal action against good-faith security research
that respects this policy and does not access other users' data, degrade
service, or exfiltrate data beyond what's needed to demonstrate the issue.

## No bounty (yet)

There's no paid bounty program at this stage. Credit in the changelog and our
sincere thanks are the current reward.

## Supported versions

The latest released version on PyPI receives security fixes. Pin a version and
watch releases for security advisories.
