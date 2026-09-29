"""bastion.memory_persistence: the first detector through the shadow gate.

Targets memory poisoning (corpus 0.4.0, tactic `memory-poisoning`): text telling the
agent to persist something into memory AND re-emit it in every future output. It
shipped `experimental` (shadow) in 0.12 and was promoted to stable (enforce) in 0.13.0
on evidence: 3/3 corpus attacks, 0 false positives. The kill switch still turns it off.
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
    assert spec.status == "stable" and spec.default_mode == "enforce"


@pytest.mark.parametrize("row_id", ATTACKS)
def test_attack_blocks_by_default(row_id):
    verdict = Firewall(log=EventLog(None)).check_tool_result(ROWS[row_id].text)
    assert verdict.allowed is False and "memory_persistence" in verdict.matches
    assert verdict.shadow_hits == ()


@pytest.mark.parametrize("row_id", ATTACKS)
def test_kill_switch_turns_it_off(row_id):
    # it is the only signature on these rows, so off really means allowed
    fw = Firewall(log=EventLog(None), inbound=InboundGuard(modes={ID: "off"}))
    verdict = fw.check_tool_result(ROWS[row_id].text)
    assert verdict.allowed is True and "memory_persistence" not in verdict.matches


@pytest.mark.parametrize("row_id", ATTACKS)
def test_can_be_put_back_in_shadow(row_id):
    fw = Firewall(log=EventLog(None), inbound=InboundGuard(modes={ID: "shadow"}))
    verdict = fw.check_tool_result(ROWS[row_id].text)
    assert verdict.allowed is True and ID in verdict.shadow_hits and verdict.would_flip


def test_benign_memory_trap_does_not_match():
    matches, _, shadow = HeuristicDetector().scan_detailed(ROWS["benign_memory-001"].text)
    assert "memory_persistence" not in matches and shadow == ()


def test_no_false_positives_on_any_benign_input():
    detector = HeuristicDetector()
    hits = [t[:60] for t in _benign_texts() if "memory_persistence" in detector.scan_detailed(t)[0]]
    assert hits == []
