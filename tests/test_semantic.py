"""#5: semantic (embedding) detection via a fake embed_fn - deterministic, no
model/network. Cosine threshold logic + InboundGuard integration + fail-soft."""

import httpx

from agentbastion.inbound import InboundGuard
from agentbastion.semantic import SemanticDetector, _cosine, http_embedder


# A fake embedder: maps known strings to fixed unit vectors so cosine is exact.
_VECTORS = {
    "TEMPLATE": [1.0, 0.0, 0.0],
    "PARAPHRASE": [0.98, 0.20, 0.0],   # ~0.98 cosine to TEMPLATE -> flagged
    "UNRELATED": [0.0, 1.0, 0.0],      # orthogonal -> 0.0 -> not flagged
}


def _fake_embed(texts):
    # templates (list of the canonical intents) all map to TEMPLATE's vector;
    # test inputs map by their marker.
    out = []
    for t in texts:
        if t in _VECTORS:
            out.append(_VECTORS[t])
        else:
            out.append(_VECTORS["TEMPLATE"])  # treat template strings as TEMPLATE
    return out


def _detector(threshold=0.75):
    return SemanticDetector(_fake_embed, templates=["TEMPLATE"], threshold=threshold)


def test_cosine_basic():
    assert _cosine([1, 0, 0], [1, 0, 0]) == 1.0
    assert _cosine([1, 0, 0], [0, 1, 0]) == 0.0
    assert _cosine([1, 0, 0], [0, 0, 0]) == 0.0  # zero vector safe


def test_flags_paraphrase_above_threshold():
    m, s = _detector(threshold=0.75).scan("PARAPHRASE")
    assert m == ("semantic",) and s == 5


def test_ignores_unrelated_below_threshold():
    assert _detector(threshold=0.75).scan("UNRELATED") == ((), 0)


def test_threshold_boundary():
    # PARAPHRASE ~0.98; a threshold above it -> no flag
    assert _detector(threshold=0.99).scan("PARAPHRASE") == ((), 0)


def test_integrates_with_inbound_guard():
    g = InboundGuard(detectors=[_detector()])
    r = g.scan("PARAPHRASE")     # benign-looking to regex, flagged semantically
    assert "semantic" in r.matches
    assert g.is_blocked(r)


def test_fails_soft_on_embed_error():
    def boom(texts):
        raise RuntimeError("embedder down")
    d = SemanticDetector(boom, templates=["x"])
    assert d.scan("anything") == ((), 0)


def test_http_embedder(monkeypatch):
    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"embeddings": [[0.1, 0.2, 0.3]]}

    monkeypatch.setattr(httpx, "post", lambda url, json=None, timeout=None: _Resp())
    embed = http_embedder("https://embed.invalid")
    assert embed(["hello"]) == [[0.1, 0.2, 0.3]]


def test_gateway_wires_embedder_from_env(tmp_path, monkeypatch):
    from agentbastion.gateway import _build_firewall
    from agentbastion.semantic import SemanticDetector as SD
    monkeypatch.setenv("AGENTBASTION_EMBED_URL", "https://embed.invalid/vectors")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    fw = _build_firewall(str(tmp_path / "l.jsonl"))
    assert any(isinstance(d, SD) for d in fw.inbound.detectors)


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
