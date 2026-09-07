# Deploying the public playground demo

A one-box public demo of the guards: visitors open `/playground`, paste text,
and see the verdict; "Replay attacks" shows what gets blocked. Heuristics-only,
rate-limited, input-capped, nothing logged — safe to expose.

## Fly.io

Run from the **repo root** (not this folder) — `fly.toml` lives at the root so
the Docker build context includes `pyproject.toml`:

```bash
cd ..                                  # repo root, where fly.toml is
fly launch --copy-config --no-deploy   # choose an app name + region
fly deploy
fly open /playground
```

The root `fly.toml` sets `AGENTBASTION_PLAYGROUND=1` and no tenant keys, so only
the demo endpoints are public. Scales to zero when idle (`min_machines_running = 0`).

## Render (alternative)

New Web Service from this repo, Docker environment (root `Dockerfile`), with env:

| Key | Value |
|---|---|
| `AGENTBASTION_PLAYGROUND` | `1` |
| `AGENTBASTION_PLAYGROUND_RATE` | `30` |
| `PORT` | `8080` |

Health check path: `/healthz`.

## Security notes

- **Public demo only.** Do not set `ANTHROPIC_API_KEY` or tenant keys on this box
  — keep it heuristics-only so there's no paid-call amplification and no secrets
  to leak.
- `/v1/check/*` return `503` here (no auth configured) — expected; the demo uses
  `/v1/demo/*`.
- For a real tenant-facing gateway, deploy separately with keys, TLS, the judge,
  and a shared store — see the main README.
