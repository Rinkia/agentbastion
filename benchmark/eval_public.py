"""Deeper eval against a PUBLIC labeled dataset - a real-world catch-rate, not
the self-authored corpus.

Uses `deepset/prompt-injections` from the HuggingFace Hub (text + binary label,
1 = injection, 0 = legitimate). Optional: needs the `[bench]` extra.

    pip install "agentbastion[bench]"
    python benchmark/eval_public.py                    # test split, heuristics only
    python benchmark/eval_public.py --split train
    python benchmark/eval_public.py --dataset some/other-injection-dataset

This measures the free heuristic layer (LLM judge off) so the number is
reproducible and zero-cost. It is intentionally NOT a CI gate: the dataset is
fetched over the network and can change upstream.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from eval import evaluate, report  # noqa: E402  (reuse the same metrics)

# HF label conventions vary; treat these as "malicious".
_MALICIOUS = {1, "1", "injection", "jailbreak", "malicious", "true", True}


def load_public(dataset: str, split: str) -> list[dict]:
    try:
        from datasets import load_dataset
    except ImportError:
        sys.exit(
            "The public benchmark needs the 'datasets' library.\n"
            "  pip install \"agentbastion[bench]\""
        )

    ds = load_dataset(dataset, split=split)
    text_col = next((c for c in ("text", "prompt", "input") if c in ds.column_names), None)
    label_col = next((c for c in ("label", "labels", "is_injection") if c in ds.column_names), None)
    if text_col is None or label_col is None:
        sys.exit(f"Can't find text/label columns in {ds.column_names}")

    rows = []
    for r in ds:
        text = r[text_col]
        lab = r[label_col]
        lab_norm = lab.strip().lower() if isinstance(lab, str) else lab
        malicious = lab_norm in _MALICIOUS
        rows.append({
            "text": text,
            "label": "malicious" if malicious else "benign",
            "category": "public",
        })
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="deepset/prompt-injections")
    ap.add_argument("--split", default="test")
    args = ap.parse_args()

    rows = load_public(args.dataset, args.split)
    n_mal = sum(1 for r in rows if r["label"] == "malicious")
    print(f"dataset: {args.dataset} [{args.split}] - {len(rows)} rows "
          f"({n_mal} malicious / {len(rows) - n_mal} benign)\n")
    print(report(evaluate(rows)))


if __name__ == "__main__":
    main()
