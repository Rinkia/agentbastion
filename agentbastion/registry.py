"""Detector registry: the release status of every built-in detector.

Every detector that can influence an inbound verdict is registered here under a
namespaced ID (`bastion.<name>`). Its Sigma-style status decides its default mode:

    stable                -> enforce  (counts toward the verdict, as today)
    experimental | test   -> shadow   (runs and is reported, never blocks)

A policy.yaml v2 `detectors:` block can override any registered detector to
`off | shadow | enforce` (the kill switch). New detectors enter as `experimental`
with a `promote_in` version; CI fails once that version is reached, forcing an
explicit promote-or-re-date decision.

The registry is deliberately explicit, not derived from `inbound._SIGNATURES`: a
signature added there without an entry here fails the coverage test instead of
silently shipping enforce-by-default.
Design: policy v2 + detector modes (A1), decisions 6A / OV4 / OV5.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

Mode = Literal["off", "shadow", "enforce"]
Status = Literal["experimental", "test", "stable"]

MODES: tuple[str, ...] = ("off", "shadow", "enforce")
STATUSES: tuple[str, ...] = ("experimental", "test", "stable")

BUILTIN_NAMESPACE = "bastion."
CUSTOM_NAMESPACE = "custom."


@dataclass(frozen=True)
class DetectorSpec:
    """Release metadata for one detector (not the detector itself; see inbound.Detector)."""

    status: Status = "stable"
    promote_in: Optional[str] = None  # required unless stable

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"unknown detector status {self.status!r}; expected one of {STATUSES}")
        if self.status != "stable" and not self.promote_in:
            raise ValueError(f"a {self.status!r} detector needs promote_in (the version it must be promoted by)")

    @property
    def default_mode(self) -> Mode:
        return "enforce" if self.status == "stable" else "shadow"


_STABLE = DetectorSpec("stable")

# The signatures that shipped in 0.11.0, all stable (registering them changes no
# behavior). Do NOT append new signatures here: a new one gets its own entry in
# DETECTORS below as DetectorSpec("experimental", promote_in="<next minor>").
_SIGNATURES_AT_0_11 = (
    "ignore_previous", "ignore_your_rules", "disregard_above", "disregard_policy", "skip_safety",
    "forget_instructions", "new_instructions", "supersede_prior", "from_now_on_comply",
    "override_controls", "system_update_framing", "reveal_system_prompt", "dan_jailbreak",
    "no_restrictions", "roleplay_override", "act_as_unfiltered", "fake_system", "delimiter_marker",
    "obfuscation_decode", "cot_forgery_tag", "forged_reasoning_selfauth", "addresses_the_bot",
    "exfil_action",
    "de_ignore_previous", "de_ignore_rules", "de_forget", "de_new_instructions",
    "de_reveal_system_prompt", "de_no_restrictions",
    "fr_ignore_previous", "fr_ignore_rules", "fr_forget", "fr_new_instructions",
    "fr_reveal_system_prompt", "fr_no_restrictions",
    "es_ignore_previous", "es_ignore_rules", "es_forget", "es_new_instructions",
    "es_reveal_system_prompt", "es_no_restrictions",
    "it_ignore_previous", "it_ignore_rules", "it_forget", "it_new_instructions",
    "it_reveal_system_prompt", "it_no_restrictions",
)

# Whole-detector IDs (one verdict per detector, keyed by class-level detector_id).
SEMANTIC_ID = "bastion.semantic"
MODEL_SCANNER_ID = "bastion.model_scanner"
JUDGE_ID = "bastion.judge"

DETECTORS: dict[str, DetectorSpec] = {
    **{BUILTIN_NAMESPACE + name: _STABLE for name in _SIGNATURES_AT_0_11},
    SEMANTIC_ID: _STABLE,
    MODEL_SCANNER_ID: _STABLE,
    JUDGE_ID: _STABLE,
}
