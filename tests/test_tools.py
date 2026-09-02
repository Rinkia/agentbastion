import pytest

from agentguard.tools import ToolPolicy, ToolBlocked


def test_allow_list_permits_listed_tool():
    p = ToolPolicy(allow=frozenset({"get_ticket"}))
    assert p.check("get_ticket").allowed


def test_allow_list_denies_unlisted_tool():
    p = ToolPolicy(allow=frozenset({"get_ticket"}))
    d = p.check("delete_database")
    assert not d.allowed
    assert "allow-list" in d.reason


def test_deny_list_wins_over_allow():
    p = ToolPolicy(allow=frozenset({"send_email"}), deny=frozenset({"send_email"}))
    assert not p.check("send_email").allowed


def test_default_deny_with_no_lists():
    p = ToolPolicy(default="deny")
    assert not p.check("anything").allowed


def test_default_allow_with_no_lists():
    p = ToolPolicy(default="allow")
    assert p.check("anything").allowed


def test_rate_limit():
    p = ToolPolicy(allow=frozenset({"send_email"}), rate_limits={"send_email": 2})
    assert p.enforce("send_email").allowed
    assert p.enforce("send_email").allowed
    with pytest.raises(ToolBlocked):
        p.enforce("send_email")


def test_enforce_raises_on_deny():
    p = ToolPolicy(allow=frozenset({"get_ticket"}))
    with pytest.raises(ToolBlocked):
        p.enforce("wipe_disk")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
