"""Detector registry: coverage, status -> default mode, and signature identity.

The coverage test is the release gate: a signature added to inbound._SIGNATURES
without a registry entry fails here, so nothing ships enforce-by-default by accident.
"""

from __future__ import annotations

import re

import pytest

from agentbastion.inbound import _SIGNATURES, signature_id
from agentbastion.registry import (
    DETECTORS,
    JUDGE_ID,
    MODEL_SCANNER_ID,
    SEMANTIC_ID,
    DetectorSpec,
)

WHOLE_DETECTOR_IDS = {SEMANTIC_ID, MODEL_SCANNER_ID, JUDGE_ID}


# --- coverage --------------------------------------------------------------

def test_every_builtin_signature_is_registered():
    missing = {signature_id(s) for s in _SIGNATURES} - DETECTORS.keys()
    assert not missing, f"signatures without a registry entry: {sorted(missing)}"


def test_no_orphan_registry_entries():
    signature_ids = {signature_id(s) for s in _SIGNATURES}
    orphans = DETECTORS.keys() - signature_ids - WHOLE_DETECTOR_IDS
    assert not orphans, f"registry entries with no detector behind them: {sorted(orphans)}"


def test_whole_detectors_are_registered():
    assert WHOLE_DETECTOR_IDS <= DETECTORS.keys()


def test_existing_detectors_keep_enforcing():
    # Registering the 0.11 detectors must not change behavior (decision D-A2). Detectors
    # added later may ship in shadow; everything that shipped in 0.11 still enforces.
    from agentbastion.registry import _SIGNATURES_AT_0_11

    shipped_in_0_11 = {f"bastion.{name}" for name in _SIGNATURES_AT_0_11} | WHOLE_DETECTOR_IDS
    assert all(DETECTORS[det_id].default_mode == "enforce" for det_id in shipped_in_0_11)


# --- DetectorSpec ----------------------------------------------------------

@pytest.mark.parametrize(
    ("status", "mode"),
    [("stable", "enforce"), ("test", "shadow"), ("experimental", "shadow")],
)
def test_default_mode_derives_from_status(status, mode):
    promote_in = None if status == "stable" else "0.13.0"
    assert DetectorSpec(status, promote_in=promote_in).default_mode == mode


@pytest.mark.parametrize("status", ["experimental", "test"])
def test_non_stable_detector_requires_promote_in(status):
    with pytest.raises(ValueError, match="promote_in"):
        DetectorSpec(status)


def test_unknown_status_is_rejected():
    with pytest.raises(ValueError, match="unknown detector status"):
        DetectorSpec("beta", promote_in="0.13.0")


# --- signature identity (decision OV4) -------------------------------------

def test_builtin_signature_resolves_to_bastion_namespace():
    exfil = next(s for s in _SIGNATURES if s[0] == "exfil_action")
    assert signature_id(exfil) == "bastion.exfil_action"


def test_new_name_resolves_to_custom_namespace():
    assert signature_id(("my_rule", re.compile(r"\bsecret\b"), 4)) == "custom.my_rule"


def test_builtin_name_with_different_pattern_is_a_collision():
    with pytest.raises(ValueError, match="exfil_action"):
        signature_id(("exfil_action", re.compile(r"\bsomething else\b"), 4))


def test_builtin_name_with_different_severity_is_a_collision():
    name, pattern, severity = next(s for s in _SIGNATURES if s[0] == "exfil_action")
    with pytest.raises(ValueError, match="exfil_action"):
        signature_id((name, pattern, severity - 1))


def test_builtin_name_with_different_flags_is_a_collision():
    name, pattern, severity = next(s for s in _SIGNATURES if s[0] == "exfil_action")
    with pytest.raises(ValueError, match="exfil_action"):
        signature_id((name, re.compile(pattern.pattern), severity))  # flags dropped
