"""Evaluate the inbound guard's heuristic layer against the labeled corpus.

Offline, zero-cost (the LLM judge is off - this measures the free heuristic
layer, which is what CI can gate on). Prints a confusion matrix, precision /
recall / F1, per-category recall, and every miss (false negative) + false
positive so gaps are actionable.

    python benchmark/eval.py [path/to/corpus.jsonl]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agentbastion.inbound import InboundGuard


def load_corpus(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def evaluate(rows: list[dict], guard: InboundGuard | None = None) -> dict:
    guard = guard or InboundGuard()
    tp = fp = tn = fn = 0
    misses: list[dict] = []       # malicious we let through (false negatives)
    false_pos: list[dict] = []    # benign we blocked
    cat_total: dict[str, int] = {}
    cat_caught: dict[str, int] = {}

    for row in rows:
        malicious = row["label"] == "malicious"
        blocked = guard.is_blocked(guard.scan(row["text"]))
        if malicious:
            cat = row.get("category", "?")
            cat_total[cat] = cat_total.get(cat, 0) + 1
            if blocked:
                tp += 1
                cat_caught[cat] = cat_caught.get(cat, 0) + 1
            else:
                fn += 1
                misses.append(row)
        else:
            if blocked:
                fp += 1
                false_pos.append(row)
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
        "cat_total": cat_total, "cat_caught": cat_caught,
        "misses": misses, "false_pos": false_pos,
    }


def report(m: dict) -> str:
    lines = [
        "inbound eval",
        "=" * 44,
        f"  TP={m['tp']}  FP={m['fp']}  TN={m['tn']}  FN={m['fn']}",
        f"  precision={m['precision']:.3f}  recall={m['recall']:.3f}  F1={m['f1']:.3f}  FPR={m['fpr']:.3f}",
        "",
        "recall by attack category:",
    ]
    for cat in sorted(m["cat_total"]):
        caught, total = m["cat_caught"].get(cat, 0), m["cat_total"][cat]
        lines.append(f"  {cat:22s} {caught}/{total}")
    if m["misses"]:
        lines.append("\nMISSES (malicious, not blocked):")
        for r in m["misses"]:
            lines.append(f"  [{r.get('category')}] {r['text'][:70]}")
    if m["false_pos"]:
        lines.append("\nFALSE POSITIVES (benign, blocked):")
        for r in m["false_pos"]:
            lines.append(f"  [{r.get('category')}] {r['text'][:70]}")
    return "\n".join(lines)


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "corpus.jsonl"
    print(report(evaluate(load_corpus(path))))
