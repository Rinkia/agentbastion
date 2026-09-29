"""Consumer side of the policy.yaml contract (PRP §1.3).

agentbastion consumes the policy.yaml that `bastionsupply harden` emits. This loads
the SAME golden the producer freezes (policy_v2_harden_golden.yaml, kept
byte-identical in bastionsupply/tests/fixtures/), plus the v1 golden it emitted up to
bastionsupply 0.7 and asserts every key agentbastion
relies on still parses and enforces. If bastionsupply changes the format, this fails
here too — the break is loud on both sides, never silent.
"""

from __future__ import annotations

from pathlib import Path

from agentbastion.tools import load_policy

import pytest

FIX = Path(__file__).parent / "fixtures"
# v1 = bastionsupply harden output up to 0.7 (v1 files still load unchanged);
# v2 = its output from 0.8 on. Same decisions from both.
GOLDENS = [FIX / "policy_golden.yaml", FIX / "policy_v2_harden_golden.yaml"]
golden = pytest.mark.parametrize("GOLDEN", GOLDENS, ids=["v1", "v2"])


@golden
def test_loads_and_enforces_golden_policy(GOLDEN):
    pol = load_policy(GOLDEN)
    assert pol.default == "deny"
    assert "run_task" in pol.deny
    assert {"list_files", "sendEmail"} <= pol.allow
    assert pol.rate_limits.get("sendEmail") == 10


@golden
def test_enforcement_decisions_from_golden(GOLDEN):
    pol = load_policy(GOLDEN)
    assert pol.check("run_task").allowed is False       # on deny-list
    assert pol.check("list_files").allowed is True       # on allow-list
    assert pol.check("unknown_tool").allowed is False    # not on allow-list


@golden
def test_rate_limit_from_golden_enforced(GOLDEN):
    pol = load_policy(GOLDEN)
    # sendEmail is allowed but capped at 10/session per the golden. The counter
    # advances on record() (post-execution), so mirror real usage: check, then
    # record when allowed.
    allowed = 0
    for _ in range(12):
        if pol.check("sendEmail").allowed:
            allowed += 1
            pol.record("sendEmail")
    assert allowed == 10, f"rate limit not enforced from golden: {allowed} allowed"
