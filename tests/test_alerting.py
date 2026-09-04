"""Alerting (#10): per-tenant rules + named channel dispatch, and the env/YAML
builder. Channels are fakes - no real HTTP."""

import agentbastion.gateway_ops as ops
from agentbastion.gateway_ops import (
    AlertMonitor,
    PagerDutyChannel,
    Rule,
    SlackChannel,
    build_alert_monitor,
)


class FakeChannel:
    def __init__(self):
        self.sent = []

    def send(self, alert):
        self.sent.append(alert)


class BrokenChannel:
    def send(self, alert):
        raise RuntimeError("channel down")


def test_dispatches_to_named_channels_on_breach():
    ch = FakeChannel()
    m = AlertMonitor(Rule(2, 60, ["ops"]), {}, {"ops": ch})
    m.record_block("acme", "x")
    assert ch.sent == []
    m.record_block("acme", "y")     # 2nd -> breach
    assert len(ch.sent) == 1
    assert ch.sent[0]["tenant"] == "acme" and ch.sent[0]["count"] == 2


def test_per_tenant_rule_overrides_default():
    strict = FakeChannel()
    m = AlertMonitor(
        default_rule=Rule(5, 60, ["ops"]),
        tenant_rules={"vip": Rule(2, 60, ["ops"])},
        channels={"ops": strict},
    )
    m.record_block("vip", "x")
    m.record_block("vip", "x")      # vip threshold 2 -> fire
    assert len(strict.sent) == 1
    # a default-rule tenant at 2 blocks does NOT fire (threshold 5)
    m.record_block("other", "x")
    m.record_block("other", "x")
    assert len(strict.sent) == 1


def test_channel_failure_does_not_break_record():
    m = AlertMonitor(Rule(1, 60, ["bad", "good"]), {}, {"bad": BrokenChannel(), "good": FakeChannel()})
    m.record_block("acme", "x")     # must not raise even though 'bad' throws


def test_disabled_when_threshold_zero():
    ch = FakeChannel()
    m = AlertMonitor(Rule(0, 60, ["ops"]), {}, {"ops": ch})
    for _ in range(10):
        m.record_block("acme", "x")
    assert ch.sent == []


def test_build_from_env_webhook(monkeypatch):
    monkeypatch.delenv("AGENTBASTION_ALERT_RULES", raising=False)
    monkeypatch.setenv("AGENTBASTION_ALERT_THRESHOLD", "2")
    monkeypatch.setenv("AGENTBASTION_ALERT_WINDOW", "30")
    monkeypatch.setenv("AGENTBASTION_ALERT_WEBHOOK", "https://example.invalid/hook")
    m = build_alert_monitor()
    assert m._default.threshold == 2 and m._default.window_s == 30
    assert "default_webhook" in m._channels


def test_build_from_rules_yaml(tmp_path, monkeypatch):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "channels:\n"
        "  slack: {type: slack, url: https://hooks.slack.com/x}\n"
        "  pager: {type: pagerduty, routing_key: R1}\n"
        "default: {threshold: 5, window_s: 60, channels: [slack]}\n"
        "tenants:\n"
        "  acme: {threshold: 2, window_s: 30, channels: [slack, pager]}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENTBASTION_ALERT_RULES", str(rules))
    m = build_alert_monitor()
    assert isinstance(m._channels["slack"], SlackChannel)
    assert isinstance(m._channels["pager"], PagerDutyChannel)
    assert m._tenant_rules["acme"].threshold == 2
    assert m._default.threshold == 5


def test_slack_channel_payload(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)
    SlackChannel("https://hooks.slack.com/x").send({"tenant": "acme", "count": 3, "window_s": 60, "last_detail": "d"})
    assert "text" in captured["json"] and "acme" in captured["json"]["text"]


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
