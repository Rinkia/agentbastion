# Release checklist — agentfirewall (agentbastion)

Codifies the by-hand release we did for bastionskill so every tool ships the same way.
Publishing is automatic: pushing a **GitHub Release** tag triggers the OIDC publish workflow.

## Pre-flight

- [ ] Working tree clean, on the default branch, up to date with origin.
- [ ] CI green on the matrix (Python 3.10–3.13).
- [ ] Corpus/format contract tests green (`pytest -q`) — if this tool consumes a shared format (injections.jsonl adapters, policy.yaml, trace schema), its contract test still parses the golden fixture.

## Detector rollout (policy_version 2 / detector modes)

- [ ] **New detectors never ship enforcing.** Register every new signature/detector in
  `agentbastion/registry.py` as `DetectorSpec("experimental", promote_in="<next minor>")`,
  so it runs in **shadow** for one minor release. `tests/test_registry.py` fails if a
  signature is added without a registry entry.
- [ ] **Promote or re-date what is due.** `tests/test_registry_expiry.py` fails once
  this release (an rc counts as its release) reaches a detector's `promote_in`, or if a
  `promote_in` is more than one minor out. Promote = `status="stable"`, with a
  `BEHAVIOR:` CHANGELOG line naming the ID.
- [ ] **Verdict golden.** `tests/test_verdicts_golden.py` freezes the verdict of every
  known input. A diff means detector behavior changed: regenerate
  (`python tests/test_verdicts_golden.py --regen`) **only** when the change is intended,
  and read the fixture diff before committing. Never regenerate to make CI pass.
- [ ] **Policy format.** `tests/test_policy_v2_contract.py` locks
  `tests/fixtures/policy_v2_golden.yaml`. Changing the v2 core keys is a suite-wide
  BREAKING change (bastiongate and bastionsupply `harden` must follow).

SemVer while 0.x: **patch** = fix, no detector default change; **minor** = new policy
keys (additive), a new detector in shadow, a shadow → enforce promotion (`BEHAVIOR:`
line); **minor + `BREAKING:` line** = tightening a default, removing a policy key,
changing a shared format. Never: a new detector enforcing by default.

Version floor: `policy_version: 2` files need **agentbastion ≥ 0.12**. Older installs
ignore `detectors:` and keep enforcing, so say so in release notes that mention a kill switch.

## Bump

- [ ] Bump `__version__` in the package `__init__.py` **and** `version` in `pyproject.toml` (keep them equal).
- [ ] Update `CHANGELOG.md` (or the README changelog section) with the new version + date.

## Build & verify locally

```bash
python -m build
twine check dist/*
```

- [ ] `twine check` passes (README renders, metadata valid).

## Publish

- [ ] Tag + create a GitHub Release `v<version>` — the `publish.yml` OIDC workflow builds and uploads to PyPI.
- [ ] Confirm on PyPI: `pip install -U agentbastion` pulls the new version.

## Propagate version truth (PRP G5)

- [ ] Update `suite.json` in the **bastion-site** repo (or let the build-time `scripts/fetch-github-stats.mjs` re-fetch), so bastiondefense.dev never shows a stale version.
- [ ] `bastionsupply doctor` reports the new version as latest.
