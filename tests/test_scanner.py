"""#3: model-based scanner as a pluggable Detector. HttpScannerDetector tested
with monkeypatched httpx (no network); InboundGuard merges extra detectors."""

import httpx

from agentbastion.inbound import HttpScannerDetector, InboundGuard


class FakeDetector:
    def __init__(self, matches, severity):
        self._m = matches
        self._s = severity

    def scan(self, text):
        return tuple(self._m), self._s


def test_extra_detector_merges_and_can_block_without_heuristics():
    # benign text (no heuristic hit) but the model detector flags it -> blocked
    g = InboundGuard(detectors=[FakeDetector(("model_scanner",), 5)])
    r = g.scan("perfectly innocent looking sentence")
    assert "model_scanner" in r.matches
    assert g.is_blocked(r)


def test_detector_severity_below_threshold_flags_not_blocks():
    g = InboundGuard(block_threshold=4, detectors=[FakeDetector(("weak_signal",), 2)])
    r = g.scan("hello")
    assert "weak_signal" in r.matches
    assert not g.is_blocked(r)


class _Resp:
    def __init__(self, payload):
        self._p = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._p


def _fake_post(payload):
    def post(url, json=None, timeout=None):
        return _Resp(payload)
    return post


def test_http_scanner_flags_on_injection_bool(monkeypatch):
    monkeypatch.setattr(httpx, "post", _fake_post({"injection": True}))
    assert HttpScannerDetector("https://scanner.invalid").scan("x") == (("model_scanner",), 5)


def test_http_scanner_flags_on_score_threshold(monkeypatch):
    monkeypatch.setattr(httpx, "post", _fake_post({"score": 0.9}))
    m, s = HttpScannerDetector("https://scanner.invalid", threshold=0.5).scan("x")
    assert m == ("model_scanner",) and s == 5


def test_http_scanner_benign(monkeypatch):
    monkeypatch.setattr(httpx, "post", _fake_post({"score": 0.1, "injection": False}))
    assert HttpScannerDetector("https://scanner.invalid").scan("x") == ((), 0)


def test_http_scanner_fails_soft_on_error(monkeypatch):
    def boom(url, json=None, timeout=None):
        raise RuntimeError("scanner down")
    monkeypatch.setattr(httpx, "post", boom)
    assert HttpScannerDetector("https://scanner.invalid").scan("x") == ((), 0)


def test_gateway_wires_scanner_from_env(tmp_path, monkeypatch):
    from agentbastion.gateway import _build_firewall
    monkeypatch.setenv("AGENTBASTION_SCANNER_URL", "https://scanner.invalid/classify")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    fw = _build_firewall(str(tmp_path / "l.jsonl"))
    assert any(isinstance(d, HttpScannerDetector) for d in fw.inbound.detectors)


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
