# Changelog

## 0.12.0 (2026-09-28): detector modes, kill switch, policy v2

Final release of 0.12.0rc1, with no code changes since the rc. Everything below
(0.12.0rc1) applies. Highlights: per-detector `off | shadow | enforce` modes, the
policy-file kill switch (`policy_version: 2`, load with `Firewall.from_policy`),
shadow reporting on `Verdict` and in the audit log, and the first shadow detector,
`bastion.memory_persistence` (due for promotion by 0.13.0).

## 0.12.0rc1 (2026-09-28): detector modes, kill switch, policy v2

Release candidate. Install with `pip install --pre agentbastion` or pin `agentbastion==0.12.0rc1`.

### Added
- **Detector modes** `off | shadow | enforce` for every inbound detector, addressed by
  namespaced ID (`bastion.exfil_action`, `bastion.semantic`, `bastion.judge`, …;
  your own signatures as `custom.<name>`).
- **Kill switch**: `detectors: {bastion.<id>: off}` in a `policy_version: 2` file silences
  one detector without a release. Load with `Firewall.from_policy(path)` /
  `fw.with_policy(path)`, or the gateway's `AGENTBASTION_TOOL_POLICY`.
- **Shadow mode**: a shadow detector runs and is reported on `Verdict.shadow_hits` and
  in the audit log (`shadow_hits`, `would_flip`, `input_sha256`, `cached`), but never
  blocks. `Verdict.would_flip` marks allowed inputs that enforcing would have blocked.
- **`policy_version: 2`** loader (`load_policy_v2`), validated strictly: unknown keys,
  unknown detector IDs (with a did-you-mean hint), bad modes and contradictions fail at
  build time, never silently.
- **Detector registry** (`agentbastion.registry`) with Sigma-style status
  (`experimental | test | stable`); CI gates on `promote_in`.

### New detector (shadow)
- **BEHAVIOR:** `bastion.memory_persistence` (memory poisoning: persist something into
  memory *and* re-emit it in every future output). Ships **experimental / shadow**,
  `promote_in` 0.13.0: reported, never blocks. Catches 3/3 corpus `memory-poisoning`
  rows, 0 false positives on all benign inputs incl. the `benign_memory` trap. Opt in
  early with `bastion.memory_persistence: enforce`.

### Changed
- A policy file with `detectors:` but no `policy_version: 2` now **fails** in
  `load_policy_v2` / `from_policy` / the gateway instead of being ignored; the legacy
  `load_policy()` warns. The legacy loader also warns when a v2 file's detector modes
  cannot be applied through it.
- In `policy_version: 2`, `default:` is required only alongside `allow`/`deny`/`rate_limits`;
  a detectors-only file installs no tool policy. `default: allow` with an allow list is rejected.

### Unchanged
- No detector that shipped in 0.11 changes behavior: every verdict of all 264 known
  inputs is frozen in `tests/fixtures/verdicts_golden.json` and identical.
- v1 policy files load exactly as before.

### Note
- agentbastion ≤ 0.11 ignores `detectors:`: a kill switch needs ≥ 0.12.
