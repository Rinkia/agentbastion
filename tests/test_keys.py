"""API key lifecycle (#7): create / resolve / revoke / rotate / scopes / expiry,
as a unit and through the gateway. Security-focused: revoked and expired keys
must never authenticate; only the static admin key manages keys."""

import pytest
from fastapi.testclient import TestClient

from agentbastion import keys as keys_mod
from agentbastion.gateway import create_app
from agentbastion.keys import KeyRegistry


class FakeKVStore:
    """In-memory Store KV surface (get/set/delete/keys) for the shared-store path."""

    def __init__(self):
        self._d = {}

    def get(self, key):
        return self._d.get(key)

    def set(self, key, value, ttl_s=None):
        self._d[key] = value

    def delete(self, key):
        self._d.pop(key, None)

    def keys(self, prefix):
        return [k for k in self._d if k.startswith(prefix)]


# --- unit ---
def test_create_returns_key_once_and_no_hash_leaked():
    reg = KeyRegistry()
    raw, pub = reg.create("acme")
    assert raw and len(raw) > 20
    assert "hash" not in pub and pub["tenant"] == "acme" and pub["scopes"] == ["check"]
    assert reg.resolve(raw)["tenant"] == "acme"
    assert reg.resolve("not-the-key") is None


def test_revoke_stops_auth():
    reg = KeyRegistry()
    raw, pub = reg.create("acme")
    assert reg.revoke(pub["key_id"]) is True
    assert reg.resolve(raw) is None
    assert reg.revoke("deadbeefdead") is False  # unknown


def test_rotate_invalidates_old_keeps_tenant():
    reg = KeyRegistry()
    raw1, pub1 = reg.create("acme", ["check"])
    raw2, pub2 = reg.rotate(pub1["key_id"])
    assert reg.resolve(raw1) is None          # old dead
    assert reg.resolve(raw2)["tenant"] == "acme"
    assert pub2["key_id"] != pub1["key_id"]


def test_expiry_rejects(monkeypatch):
    reg = KeyRegistry()
    raw, _ = reg.create("acme", ttl_seconds=1000)   # expires_at set from real now
    assert reg.resolve(raw) is not None
    monkeypatch.setattr(keys_mod.time, "time", lambda: 10**12)  # jump far past expiry
    assert reg.resolve(raw) is None


def test_invalid_tenant_and_scope_rejected():
    reg = KeyRegistry()
    with pytest.raises(ValueError):
        reg.create("bad name!")
    with pytest.raises(ValueError):
        reg.create("acme", ["admin"])         # admin scope not grantable to dynamic keys


def test_shared_store_cross_instance():
    store = FakeKVStore()
    a = KeyRegistry(store)
    b = KeyRegistry(store)                     # another gateway process
    raw, pub = a.create("acme")
    assert b.resolve(raw)["tenant"] == "acme"  # b sees a's key
    b.revoke(pub["key_id"])
    assert a.resolve(raw) is None              # a sees b's revocation


# --- gateway integration ---
def _app(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTBASTION_API_KEY", "solo")
    monkeypatch.setenv("AGENTBASTION_ADMIN_KEY", "admin-secret")
    monkeypatch.setenv("AGENTBASTION_LOG", str(tmp_path / "l.jsonl"))
    monkeypatch.setenv("AGENTBASTION_USAGE", str(tmp_path / "u.json"))
    monkeypatch.delenv("AGENTBASTION_KEYS", raising=False)
    monkeypatch.delenv("AGENTBASTION_REDIS_URL", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    return TestClient(create_app())


def test_gateway_key_create_use_revoke(tmp_path, monkeypatch):
    client = _app(tmp_path, monkeypatch)
    admin = {"X-API-Key": "admin-secret"}

    # non-admin cannot create keys
    assert client.post("/v1/admin/keys", json={"tenant": "acme"}, headers={"X-API-Key": "solo"}).status_code == 403

    r = client.post("/v1/admin/keys", json={"tenant": "acme"}, headers=admin)
    assert r.status_code == 200
    body = r.json()
    new_key, key_id = body["key"], body["key_id"]

    # the new key authenticates a check
    assert client.post("/v1/check/input", json={"text": "hi"}, headers={"X-API-Key": new_key}).status_code == 200

    # revoke -> it no longer authenticates
    assert client.post(f"/v1/admin/keys/{key_id}/revoke", headers=admin).status_code == 200
    assert client.post("/v1/check/input", json={"text": "hi"}, headers={"X-API-Key": new_key}).status_code == 401


def test_gateway_bad_scope_400_and_bad_keyid_404(tmp_path, monkeypatch):
    client = _app(tmp_path, monkeypatch)
    admin = {"X-API-Key": "admin-secret"}
    assert client.post("/v1/admin/keys", json={"tenant": "acme", "scopes": ["nope"]}, headers=admin).status_code == 400
    assert client.post("/v1/admin/keys/not-a-valid-id/revoke", headers=admin).status_code == 404


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
