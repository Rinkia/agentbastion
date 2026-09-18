"""Consumer contract: agentbastion still parses the shared corpus (PRP §1.3).

agentbastion's SemanticDetector sources its intent templates from bastioncorpus
via `to_semantic`. `_default_templates` swallows any error and falls back to a
tiny built-in set — recall degrades silently. This test asserts the corpus path
actually engaged (templates differ from, and exceed, the built-in fallback).
"""

from __future__ import annotations

from bastioncorpus import load_corpus, to_semantic

from agentbastion.semantic import _BUILTIN_TEMPLATES, _default_templates


def test_semantic_contract_shape():
    out = to_semantic(load_corpus())
    assert set(out) == {"templates", "corpus"}
    assert out["templates"] and all(isinstance(t, str) for t in out["templates"])
    assert out["corpus"]
    row = out["corpus"][0]
    assert set(row) == {"text", "label", "category"}


def test_default_templates_use_corpus_not_fallback():
    templates = _default_templates()
    assert templates, "no templates loaded"
    assert templates != _BUILTIN_TEMPLATES, (
        "agentbastion fell back to built-in templates — the corpus to_semantic "
        "contract broke and enrichment is silently off"
    )
