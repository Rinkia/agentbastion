"""Regression gate: the inbound heuristic layer must hold its catch-rate on the
labeled corpus without blocking benign traffic.

Thresholds sit below the current 1.0/0.0 on purpose - headroom so that adding
harder examples to the corpus later flags a real regression instead of an
instant fail. The corpus is small and self-authored, so these numbers prove
coverage of known attack *shapes*, not a real-world catch-rate. Raise the bar
(and the corpus) as harder cases land.
"""

import sys
from pathlib import Path

_BENCH = Path(__file__).parents[1] / "benchmark"
sys.path.insert(0, str(_BENCH))

from eval import evaluate, load_corpus  # noqa: E402

RECALL_MIN = 0.85
FPR_MAX = 0.05

_metrics = evaluate(load_corpus(_BENCH / "corpus.jsonl"))


def test_recall_meets_threshold():
    assert _metrics["recall"] >= RECALL_MIN, (
        f"recall {_metrics['recall']:.3f} < {RECALL_MIN}; misses: "
        f"{[r['text'][:50] for r in _metrics['misses']]}"
    )


def test_false_positive_rate_within_bound():
    assert _metrics["fpr"] <= FPR_MAX, (
        f"FPR {_metrics['fpr']:.3f} > {FPR_MAX}; false positives: "
        f"{[r['text'][:50] for r in _metrics['false_pos']]}"
    )


def test_every_attack_category_has_some_coverage():
    # No whole category should be entirely missed.
    for cat, total in _metrics["cat_total"].items():
        caught = _metrics["cat_caught"].get(cat, 0)
        assert caught > 0, f"attack category '{cat}' fully missed (0/{total})"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
