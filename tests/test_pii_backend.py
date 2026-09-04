"""#4: pluggable PII backend. Regex stays default; Presidio is opt-in and
falls back cleanly when not installed. Firewall.outbound is duck-typed."""

import pytest

from agentbastion import Firewall
from agentbastion.events import EventLog
from agentbastion.outbound import PiiFinding, PiiRedactor, build_redactor


class FakeRedactor:
    def redact(self, text):
        # redacts the literal word SECRET, returns findings list
        i = text.find("SECRET")
        if i >= 0:
            return text.replace("SECRET", "<REDACTED:FAKE>"), [PiiFinding("FAKE", "SECRET", i, i + 6)]
        return text, []


def test_build_redactor_defaults_to_regex(monkeypatch):
    monkeypatch.delenv("AGENTBASTION_PII_BACKEND", raising=False)
    assert isinstance(build_redactor(), PiiRedactor)


def test_build_redactor_presidio_falls_back_when_missing(monkeypatch):
    # presidio not installed in CI -> PresidioRedactor() raises ImportError -> regex
    monkeypatch.setenv("AGENTBASTION_PII_BACKEND", "presidio")
    assert isinstance(build_redactor(), PiiRedactor)


def test_firewall_uses_any_duck_typed_redactor(tmp_path):
    fw = Firewall(outbound=FakeRedactor(), log=EventLog(tmp_path / "e.jsonl"))
    redacted, _ = fw.check_output("the SECRET is out")
    assert "SECRET" not in redacted and "<REDACTED:FAKE>" in redacted


def test_presidio_redactor_if_installed():
    presidio = pytest.importorskip("presidio_analyzer")  # skipped in CI (no dep)
    from agentbastion.outbound import PresidioRedactor
    red = PresidioRedactor()
    out, findings = red.redact("My name is John Smith and I live in New York.")
    assert findings  # detected a PERSON / LOCATION
    assert "<REDACTED:" in out


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
