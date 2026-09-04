"""#12: compliance/audit - filtered export, retention prune, log-detail redaction."""

import json

from fastapi.testclient import TestClient

from agentbastion.events import Event, EventLog, export_events, prune_events
from agentbastion.gateway import create_app
from agentbastion.outbound import PiiRedactor


def _write(path, events):
    log = EventLog(path)
    for e in events:
        log.log(e)


def test_export_filters_by_tenant_and_format(tmp_path):
    p = tmp_path / "log.jsonl"
    _write(p, [
        Event("inbound", "allow", "ok", {"tenant": "acme"}, ts="2026-01-01T00:00:00+00:00"),
        Event("inbound", "block", "sig", {"tenant": "beta"}, ts="2026-01-02T00:00:00+00:00"),
    ])
    out = export_events(p, tenant="acme")
    lines = [json.loads(x) for x in out.splitlines()]
    assert len(lines) == 1 and lines[0]["extra"]["tenant"] == "acme"

    csv_out = export_events(p, fmt="csv")
    assert csv_out.splitlines()[0] == "ts,stage,decision,tenant,detail"
    assert "beta" in csv_out


def test_export_filters_by_time(tmp_path):
    p = tmp_path / "log.jsonl"
    _write(p, [
        Event("inbound", "allow", "a", {}, ts="2026-01-01T00:00:00+00:00"),
        Event("inbound", "allow", "b", {}, ts="2026-06-01T00:00:00+00:00"),
    ])
    out = export_events(p, since="2026-03-01T00:00:00+00:00")
    assert len(out.splitlines()) == 1 and "b" in out


def test_prune_removes_old_events(tmp_path):
    from datetime import datetime, timedelta, timezone
    p = tmp_path / "log.jsonl"
    old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    new = datetime.now(timezone.utc).isoformat()
    _write(p, [Event("inbound", "allow", "old", {}, ts=old),
               Event("inbound", "allow", "new", {}, ts=new)])
    removed = prune_events(p, older_than_days=30)
    assert removed == 1
    remaining = p.read_text(encoding="utf-8")
    assert "new" in remaining and "old" not in remaining


def test_log_redaction_scrubs_detail(tmp_path):
    p = tmp_path / "log.jsonl"
    log = EventLog(p, redactor=PiiRedactor())
    log.log(Event("outbound", "redact", "leaked bob@corp.com in reply", {}))
    written = p.read_text(encoding="utf-8")
    assert "bob@corp.com" not in written and "<REDACTED:EMAIL>" in written


def test_gateway_audit_endpoints_admin_only(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTBASTION_API_KEY", "solo")
    monkeypatch.setenv("AGENTBASTION_ADMIN_KEY", "admin-secret")
    monkeypatch.setenv("AGENTBASTION_LOG", str(tmp_path / "l.jsonl"))
    monkeypatch.setenv("AGENTBASTION_USAGE", str(tmp_path / "u.json"))
    monkeypatch.delenv("AGENTBASTION_KEYS", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = TestClient(create_app())
    client.post("/v1/check/input", json={"text": "hi"}, headers={"X-API-Key": "solo"})

    assert client.get("/v1/audit/export", headers={"X-API-Key": "solo"}).status_code == 403
    r = client.get("/v1/audit/export", headers={"X-API-Key": "admin-secret"})
    assert r.status_code == 200
    assert client.get("/v1/audit/export?format=xml", headers={"X-API-Key": "admin-secret"}).status_code == 400
    assert client.post("/v1/audit/prune?older_than_days=0", headers={"X-API-Key": "admin-secret"}).status_code == 400
    assert client.post("/v1/audit/prune?older_than_days=30", headers={"X-API-Key": "admin-secret"}).status_code == 200


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
