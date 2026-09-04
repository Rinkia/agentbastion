# SPDX-License-Identifier: BUSL-1.1
# Part of the agentbastion commercial gateway. Licensed under the Business Source
# License 1.1 (see LICENSE-BSL), NOT MIT. Converts to Apache-2.0 on the Change Date.
"""Dynamic API-key lifecycle: create, rotate, revoke, scopes, expiry (#7).

Complements the static keys file: those keys are the operator's bootstrap, this
is the runtime-managed set. Records are backed by the shared store (#6) when
present so rotation/revocation take effect across every gateway process; without
a store they live in-process (single-process only).

Security:
  - Keys are generated with secrets.token_urlsafe(32) (high entropy) and are
    returned in plaintext exactly ONCE, at creation. Only the SHA-256 hash is
    stored; the plaintext is never persisted or logged.
  - key_id = first 12 hex of the hash: a non-reversible public handle for
    listing/revoking without exposing the key.
  - resolve() confirms the full hash with a constant-time compare and enforces
    expiry. Revoked/expired keys never authenticate.
  - Only the static admin key manages keys (enforced at the endpoint), so a
    leaked tenant key cannot mint or escalate keys.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Optional

_PREFIX = "ab:key:"
_VALID_TENANT = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_VALID_SCOPES = {"check"}  # v0: dynamic keys can only be granted the check scope


def _sha(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class KeyRegistry:
    def __init__(self, store=None) -> None:
        self._store = store
        self._mem: dict[str, dict] = {}

    # --- persistence helpers ---
    def _put(self, rec: dict, ttl_s: Optional[int]) -> None:
        if self._store is not None:
            self._store.set(_PREFIX + rec["key_id"], json.dumps(rec), ttl_s)
        else:
            self._mem[rec["key_id"]] = rec

    def _fetch(self, key_id: str) -> Optional[dict]:
        if self._store is not None:
            raw = self._store.get(_PREFIX + key_id)
            return json.loads(raw) if raw else None
        return self._mem.get(key_id)

    def _remove(self, key_id: str) -> None:
        if self._store is not None:
            self._store.delete(_PREFIX + key_id)
        else:
            self._mem.pop(key_id, None)

    @staticmethod
    def _public(rec: dict) -> dict:
        return {k: rec[k] for k in ("key_id", "tenant", "scopes", "expires_at", "created_at")}

    # --- lifecycle ---
    def create(self, tenant: str, scopes: Optional[list[str]] = None, ttl_seconds: Optional[int] = None) -> tuple[str, dict]:
        if not _VALID_TENANT.match(tenant or ""):
            raise ValueError("invalid tenant name (allowed: A-Z a-z 0-9 _ . - , 1-64 chars)")
        scopes = scopes or ["check"]
        bad = set(scopes) - _VALID_SCOPES
        if bad:
            raise ValueError(f"invalid scope(s): {sorted(bad)}; allowed: {sorted(_VALID_SCOPES)}")
        raw = secrets.token_urlsafe(32)
        h = _sha(raw)
        now = int(time.time())
        rec = {
            "key_id": h[:12],
            "tenant": tenant,
            "scopes": scopes,
            "hash": h,
            "created_at": now,
            "expires_at": (now + ttl_seconds) if ttl_seconds else None,
        }
        self._put(rec, ttl_seconds)
        return raw, self._public(rec)  # plaintext returned once

    def resolve(self, presented_key: str) -> Optional[dict]:
        """Return the record for a valid, unexpired key, else None."""
        if not presented_key:
            return None
        h = _sha(presented_key)
        rec = self._fetch(h[:12])
        if not rec or not hmac.compare_digest(rec.get("hash", ""), h):
            return None
        exp = rec.get("expires_at")
        if exp is not None and time.time() >= exp:
            self._remove(rec["key_id"])  # opportunistic cleanup
            return None
        return rec

    def revoke(self, key_id: str) -> bool:
        if self._fetch(key_id) is None:
            return False
        self._remove(key_id)
        return True

    def rotate(self, key_id: str) -> Optional[tuple[str, dict]]:
        rec = self._fetch(key_id)
        if rec is None:
            return None
        ttl = None
        if rec.get("expires_at"):
            ttl = max(1, int(rec["expires_at"] - time.time()))  # preserve remaining lifetime
        raw, pub = self.create(rec["tenant"], rec.get("scopes"), ttl)
        self._remove(key_id)
        return raw, pub

    def list(self) -> list[dict]:
        recs: list[dict] = []
        if self._store is not None:
            for full in self._store.keys(_PREFIX):
                raw = self._store.get(full)
                if raw:
                    recs.append(self._public(json.loads(raw)))
        else:
            recs = [self._public(r) for r in self._mem.values()]
        return recs
