"""Per-row verdict golden: the "no behavior change for existing detectors" gate.

test_honest.py only asserts fpr == 0 and recall >= 0.7, so a detector change could
drop recall or swap which rows are caught and CI would stay green. This freezes the
exact verdict (allowed, matches, reason) of every known input on BOTH inbound stages
(check_input and check_tool_result), captured on agentbastion 0.11.0 before the
policy-v2 / detector-modes work (design A1, eng review OV3).

The golden stores each input's text, so it does not depend on the installed
bastioncorpus version. Only a verdict change can fail it.

Regenerate ONLY when a verdict change is intended, and read the diff before committing:
    python tests/test_verdicts_golden.py --regen
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agentbastion import Firewall
from agentbastion.events import EventLog

ROOT = Path(__file__).parents[1]
GOLDEN = Path(__file__).parent / "fixtures" / "verdicts_golden.json"
BENCH_FILES = ("benchmark/corpus.jsonl", "benchmark/honest_corpus.jsonl")


def _inputs() -> list[dict]:
    from bastioncorpus import load_corpus

    rows = [{"src": "bastioncorpus", "key": r.id, "text": r.text} for r in load_corpus()]
    for rel in BENCH_FILES:
        for n, line in enumerate((ROOT / rel).read_text(encoding="utf-8").splitlines(), 1):
            if line.strip():
                rows.append({"src": rel, "key": f"L{n}", "text": json.loads(line)["text"]})
    return rows


def _verdicts(fw: Firewall, text: str) -> dict:
    out = {}
    for stage, check in (("input", fw.check_input), ("tool_result", fw.check_tool_result)):
        v = check(text)
        out[stage] = [v.allowed, list(v.matches), v.reason]
    return out


def _firewall() -> Firewall:
    # Heuristics only: deterministic and offline (no judge, no embedder, no disk log).
    return Firewall(log=EventLog(None))


def test_every_verdict_matches_golden():
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    fw = _firewall()
    drift = []
    for row in golden["rows"]:
        now = _verdicts(fw, row["text"])
        for stage in ("input", "tool_result"):
            if now[stage] != row[stage]:
                drift.append(f"{row['src']}:{row['key']} [{stage}] {row[stage]} -> {now[stage]}")
    assert not drift, f"{len(drift)} verdict(s) changed:\n" + "\n".join(drift)


def _regen() -> None:
    import agentbastion

    fw = _firewall()
    rows = [{**r, **_verdicts(fw, r["text"])} for r in _inputs()]
    GOLDEN.write_text(
        json.dumps({"captured_on": f"agentbastion {agentbastion.__version__}", "rows": rows},
                   indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    blocked = sum(not r["input"][0] for r in rows)
    print(f"wrote {len(rows)} rows ({blocked} blocked on input) -> {GOLDEN}")


if __name__ == "__main__" and "--regen" in sys.argv:
    _regen()
