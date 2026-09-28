# TODOS

## Gateway

### Inline policy delivery for a hosted gateway

**What:** Support `AGENTBASTION_TOOL_POLICY_YAML` (policy content passed in an env var / Fly secret) alongside the existing file path.

**Why:** Once a real hosted multi-tenant gateway exists, `fly secrets set` could flip a detector kill switch in seconds with no image rebuild. Today a policy has to be a mounted file.

**Context:** `agentbastion/gateway.py:129-131` reads only `AGENTBASTION_TOOL_POLICY` (a path). The only Fly app today (`fly.toml`, `agentbastion-demo`) is the public playground, with no policy and no tenants. Eng review decision 1A deliberately built no infra for it (design doc `~/.gstack/projects/Varie/stefano-bastion-release-design-20260927-232415.md`). Route the YAML string through the same `load_policy_v2` validation, not a second parser.

**Effort:** S
**Priority:** P3
**Depends on:** A1 (policy v2 + detector modes, agentbastion 0.12.0) shipped; a real hosted gateway running in production.

## Completed
