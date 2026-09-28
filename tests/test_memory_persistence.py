"""bastion.memory_persistence: the first detector to ship through the shadow gate.

Targets memory poisoning (corpus 0.4.0, tactic `memory-poisoning`): text telling the
agent to persist something into memory AND re-emit it in every future output. It
ships `experimental` (shadow) with promote_in = next minor: it is reported on
Verdict.shadow_hits and in the audit log, never blocks, until promoted on evidence.
The benign trap `benign_memory-001` ("remember ... for future reports") has no
"every future output" clause and must not match.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from bastioncorpus import load_corpus

from agentbastion import Firewall
from agentbastion.events import EventLog
from agentbastion.inbound import HeuristicDetector, InboundGuard
from agentbastion.registry import DETECTORS

ID = "bastion.memory_persistence"
ROWS = {r.id: r for r in load_corpus()}
ATTACKS = ["mp-fire-001", "mp-fire-002", "mp-fire-003"]
BENCH = Path(__file__).parents[1] / "benchmark"


def _benign_texts() -> list[str]:
    texts = [r.text for r in ROWS.values() if not r.is_malicious]
    for name in ("corpus.jsonl", "honest_corpus.jsonl"):
        for line in (BENCH / name).read_text(encoding="utf-8").splitlines():
            if line.strip() and json.loads(line).get("label") == "benign":
                texts.append(json.loads(line)["text"])
    return texts


def test_registered_as_a_shadow_detector():
    spec = DETECTORS[ID]
    assert spec.status == "experimental" and spec.default_mode == "shadow"
    assert spec.promote_in == "0.13.0"


@pytest.mark.parametrize("row_id", ATTACKS)
def test_attack_is_reported_in_shadow_but_not_blocked(row_id):
    verdict = Firewall(log=EventLog(None)).check_tool_result(ROWS[row_id].text)
    assert verdict.allowed is True  # shadow: never blocks
    assert ID in verdict.shadow_hits
    assert verdict.would_flip is True  # would have been blocked if enforced


@pytest.mark.parametrize("row_id", ATTACKS)
def test_attack_blocks_when_enforced(row_id):
    fw = Firewall(log=EventLog(None), inbound=InboundGuard(modes={ID: "enforce"}))
    verdict = fw.check_tool_result(ROWS[row_id].text)
    assert verdict.allowed is False and "memory_persistence" in verdict.matches


def test_benign_memory_trap_does_not_match():
    _, _, shadow = HeuristicDetector().scan_detailed(ROWS["benign_memory-001"].text)
    assert shadow == ()


def test_no_false_positives_on_any_benign_input():
    detector = HeuristicDetector()
    hits = [t[:60] for t in _benign_texts() if any(i == ID for i, _ in detector.scan_detailed(t)[2])]
    assert hits == []
