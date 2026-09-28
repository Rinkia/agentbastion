"""Release gate for shadow detectors (decisions D-A4, OV5, OV7).

A non-stable detector runs in shadow: it protects nobody until promoted. So:
1. OVERDUE: once the shipping version reaches its `promote_in`, CI fails. An rc
   counts as its release (0.13.0rc1 is 0.13.0), so the decision lands before the
   release candidate ships. Fix: promote it (status="stable") or re-date it.
2. WINDOW: `promote_in` may be at most the next minor, so a detector can't be parked
   in shadow indefinitely; re-dating moves it one minor at a time, deliberately.
Versions are compared as packaging.version.Version(...).release tuples, never as
strings ("0.9" > "0.14" as strings).
"""

from __future__ import annotations

from packaging.version import Version

import agentbastion
from agentbastion.registry import DETECTORS, DetectorSpec


def _release(version: str) -> tuple[int, ...]:
    release = Version(version).release
    return release + (0,) * (3 - len(release))  # "0.13" -> (0, 13, 0)


def _next_minor(version: str) -> tuple[int, ...]:
    major, minor = _release(version)[:2]
    return (major, minor + 1, 0)


def expiry_problems(detectors: dict[str, DetectorSpec], version: str) -> list[str]:
    now, limit = _release(version), _next_minor(version)
    problems = []
    for det_id, spec in sorted(detectors.items()):
        if spec.status == "stable":
            continue
        due = _release(spec.promote_in)
        if now >= due:
            problems.append(f"{det_id}: OVERDUE, promote_in {spec.promote_in} <= {version}; "
                            "promote it (status='stable') or re-date it")
        elif due > limit:
            problems.append(f"{det_id}: promote_in {spec.promote_in} is beyond the next minor "
                            f"({'.'.join(map(str, limit))}); shadow windows are one minor at most")
    return problems


def test_registry_has_no_overdue_or_parked_shadow_detectors():
    problems = expiry_problems(DETECTORS, agentbastion.__version__)
    assert not problems, "\n".join(problems)


# --- the checker itself -----------------------------------------------------

def _shadow(promote_in: str) -> dict[str, DetectorSpec]:
    return {"bastion.new_rule": DetectorSpec("experimental", promote_in=promote_in)}


def test_stable_detectors_never_expire():
    assert expiry_problems({"bastion.x": DetectorSpec("stable")}, "9.9.9") == []


def test_due_next_minor_is_fine():
    assert expiry_problems(_shadow("0.13.0"), "0.12.0") == []


def test_overdue_on_the_release_itself():
    assert "OVERDUE" in expiry_problems(_shadow("0.13.0"), "0.13.0")[0]


def test_release_candidate_counts_as_its_release():
    assert "OVERDUE" in expiry_problems(_shadow("0.13.0"), "0.13.0rc1")[0]


def test_patch_releases_before_the_deadline_are_fine():
    assert expiry_problems(_shadow("0.13.0"), "0.12.5") == []


def test_numeric_not_string_comparison():
    # As strings "0.9.0" > "0.14.0"; as versions 0.9 < 0.14.
    assert expiry_problems(_shadow("0.10.0"), "0.9.0") == []
    assert "OVERDUE" in expiry_problems(_shadow("0.9.0"), "0.14.0")[0]


def test_window_longer_than_one_minor_is_rejected():
    assert "beyond the next minor" in expiry_problems(_shadow("0.14.0"), "0.12.0")[0]


def test_short_version_strings():
    assert expiry_problems(_shadow("0.13"), "0.12") == []
    assert "OVERDUE" in expiry_problems(_shadow("0.13"), "0.13.0")[0]
