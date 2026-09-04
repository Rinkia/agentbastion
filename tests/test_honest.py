"""Honest benchmark: on a cleanly-labeled set (roleplay/codegen are benign, not
injection), the guard must NOT block benign roleplay (FPR 0) and should catch
the blatant injections. Heuristics-only here; the multilingual judge lifts the
non-English residual (e.g. the Spanish row)."""

import sys
from pathlib import Path

_BENCH = Path(__file__).parents[1] / "benchmark"
sys.path.insert(0, str(_BENCH))

from eval import evaluate, load_corpus  # noqa: E402

_m = evaluate(load_corpus(_BENCH / "honest_corpus.jsonl"))


def test_no_false_positives_on_benign_roleplay_and_codegen():
    # The whole point: benign roleplay / codegen / support must pass.
    assert _m["fpr"] == 0.0, f"false positives: {[r['text'][:50] for r in _m['false_pos']]}"


def test_catches_blatant_injections_heuristics_only():
    # English + German injections are caught offline; the Spanish one needs the
    # judge, so heuristics-only recall is high but not necessarily 1.0.
    assert _m["recall"] >= 0.7, f"recall {_m['recall']:.2f}; misses {[r['text'][:40] for r in _m['misses']]}"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
