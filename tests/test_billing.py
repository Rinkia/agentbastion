"""Metered billing: delta computation, state persistence, customer mapping, and
the admin billing endpoint. No Stripe - a fake backend captures reports."""

from fastapi.testclient import TestClient

from agentbastion.billing import BillingReporter, NullBackend
from agentbastion.gateway import create_app
from agentbastion.gateway_ops import UsageMeter


class _FakeBackend:
    def __init__(self):
        self.calls = []

    def report(self, customer, quantity):
        self.calls.append((customer, quantity))


def test_reports_delta_then_nothing_then_new_delta(tmp_path):
    meter = UsageMeter(str(tmp_path / "u.json"))
    backend = _FakeBackend()
    state = str(tmp_path / "state.json")
    reporter = BillingReporter(meter, backend, {"acme": "cus_1"}, state)

    for _ in range(3):
        meter.record("acme", "input")
    out = reporter.report()
    assert out["acme"]["reported"] == 3
    assert backend.calls == [("cus_1", 3)]

    # nothing new -> no report
    assert reporter.report() == {}
    assert len(backend.calls) == 1

    # more usage -> only the delta
    meter.record("acme", "tool")
    meter.record("acme", "output")
    out = reporter.report()
    assert out["acme"]["reported"] == 2
    assert backend.calls[-1] == ("cus_1", 2)


def test_state_persists_across_reporter_instances(tmp_path):
    meter = UsageMeter(str(tmp_path / "u.json"))
    state = str(tmp_path / "state.json")
    for _ in range(5):
        meter.record("acme", "input")
    BillingReporter(meter, _FakeBackend(), {"acme": "cus_1"}, state).report()
    # fresh reporter reads persisted state -> no double billing
    b2 = _FakeBackend()
    assert BillingReporter(meter, b2, {"acme": "cus_1"}, state).report() == {}
    assert b2.calls == []


def test_unmapped_tenant_is_skipped_not_billed(tmp_path):
    meter = UsageMeter(str(tmp_path / "u.json"))
    meter.record("ghost", "input")
    backend = _FakeBackend()
    out = BillingReporter(meter, backend, {}, str(tmp_path / "s.json")).report()
    assert out["ghost"]["reported"] == 0
    assert "no stripe customer" in out["ghost"]["skipped"]
    assert backend.calls == []


def test_null_backend_does_not_raise(tmp_path):
    meter = UsageMeter(str(tmp_path / "u.json"))
    meter.record("acme", "input")
    out = BillingReporter(meter, NullBackend(), {"acme": "cus_1"}, str(tmp_path / "s.json")).report()
    assert out["acme"]["reported"] == 1


def test_gateway_billing_endpoint_admin_only(tmp_path, monkeypatch):
    cmap = tmp_path / "map.json"
    cmap.write_text('{"default": "cus_default"}', encoding="utf-8")
    monkeypatch.setenv("AGENTBASTION_API_KEY", "solo")
    monkeypatch.setenv("AGENTBASTION_ADMIN_KEY", "admin-secret")
    monkeypatch.setenv("AGENTBASTION_LOG", str(tmp_path / "l.jsonl"))
    monkeypatch.setenv("AGENTBASTION_USAGE", str(tmp_path / "u.json"))
    monkeypatch.setenv("AGENTBASTION_BILLING_MAP", str(cmap))
    monkeypatch.setenv("AGENTBASTION_BILLING_STATE", str(tmp_path / "state.json"))
    monkeypatch.delenv("AGENTBASTION_KEYS", raising=False)
    monkeypatch.delenv("AGENTBASTION_STRIPE_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = TestClient(create_app())

    client.post("/v1/check/input", json={"text": "hi"}, headers={"X-API-Key": "solo"})
    client.post("/v1/check/input", json={"text": "hello"}, headers={"X-API-Key": "solo"})

    assert client.post("/v1/billing/report", headers={"X-API-Key": "solo"}).status_code == 403
    r = client.post("/v1/billing/report", headers={"X-API-Key": "admin-secret"})
    assert r.status_code == 200
    assert r.json()["reported"]["default"]["reported"] == 2


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
