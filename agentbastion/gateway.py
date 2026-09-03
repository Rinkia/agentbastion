"""HTTP gateway - the hosted tier. A FastAPI service in front of the same
`Firewall` the SDK uses, with multi-tenant API keys and an admin dashboard.

Run:
    pip install "agentbastion[gateway,judge]"
    export AGENTBASTION_API_KEY=<secret>          # single-tenant, or:
    export AGENTBASTION_KEYS=keys.yaml            # multi-tenant (see keys.example.yaml)
    export ANTHROPIC_API_KEY=...                  # optional: enables the judge
    agentbastion-gateway                          # serves on :8080

Auth model:
    - Tenant keys hit /v1/check/*; each request is tagged with its tenant in the
      audit log. Keys are looked up by SHA-256 (constant-ish, no plaintext compare
      loop). ponytail: keys are stored plaintext in the keys file (operator's
      secret); hashing them at rest is the next hardening step.
    - An admin key gates /v1/stats and the /dashboard data. The /dashboard HTML
      shell is public (carries no data); it asks for the admin key in-browser and
      fetches /v1/stats with the X-API-Key header (key never goes in the URL).

Config (env):
    AGENTBASTION_KEYS         path to a keys YAML: {admin_key, tenants: {name: key}}
    AGENTBASTION_API_KEY      single-tenant key (tenant "default") if KEYS unset
    AGENTBASTION_ADMIN_KEY    admin key (single-tenant mode)
    AGENTBASTION_ALLOW_NO_AUTH=1   dev only: no auth (loud, unsafe)
    AGENTBASTION_TOOL_POLICY  tool-policy YAML path (enables /v1/check/tool)
    AGENTBASTION_LOG          audit-log path (default agentbastion.jsonl)
    ANTHROPIC_API_KEY         if set, the inbound LLM judge is enabled
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .events import EventLog
from .events import stats as log_stats
from .firewall import Firewall
from .tools import load_policy


def _sha(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class AuthStore:
    """SHA-256 keyed tenant lookup + admin check. No plaintext key comparisons."""

    def __init__(self, tenants: dict[str, str], admin_key: str | None) -> None:
        self._by_hash = {_sha(k): name for name, k in tenants.items() if k}
        self._admin_hash = _sha(admin_key) if admin_key else None

    @property
    def configured(self) -> bool:
        return bool(self._by_hash) or self._admin_hash is not None

    def tenant_for(self, key: str) -> str | None:
        return self._by_hash.get(_sha(key)) if key else None

    def is_admin(self, key: str) -> bool:
        return bool(key) and self._admin_hash is not None and hmac.compare_digest(_sha(key), self._admin_hash)


def _load_auth() -> AuthStore:
    keys_path = os.getenv("AGENTBASTION_KEYS")
    if keys_path:
        import yaml

        data = yaml.safe_load(Path(keys_path).read_text(encoding="utf-8")) or {}
        return AuthStore(dict(data.get("tenants") or {}), data.get("admin_key"))
    single = os.getenv("AGENTBASTION_API_KEY")
    return AuthStore({"default": single} if single else {}, os.getenv("AGENTBASTION_ADMIN_KEY"))


def _build_firewall(log_path: str) -> Firewall:
    log = EventLog(log_path)
    if os.getenv("ANTHROPIC_API_KEY"):
        import anthropic

        fw = Firewall.with_judge(anthropic.Anthropic(), log=log)
    else:
        fw = Firewall(log=log)
    policy_path = os.getenv("AGENTBASTION_TOOL_POLICY")
    if policy_path:
        fw.tool_policy = load_policy(policy_path)
    return fw


class TextIn(BaseModel):
    text: str


class InputVerdict(BaseModel):
    allowed: bool
    reason: str
    matches: list[str]


class OutputVerdict(BaseModel):
    redacted: str
    findings: list[str]


class ToolIn(BaseModel):
    name: str
    input: dict | None = None


class ToolVerdict(BaseModel):
    allowed: bool
    reason: str


def create_app() -> FastAPI:
    log_path = os.getenv("AGENTBASTION_LOG", "agentbastion.jsonl")
    firewall = _build_firewall(log_path)
    auth = _load_auth()
    allow_no_auth = os.getenv("AGENTBASTION_ALLOW_NO_AUTH") == "1"
    judge_on = firewall.inbound.judge is not None

    app = FastAPI(title="agentbastion gateway", version="0.4.0")

    def require_tenant(x_api_key: str = Header(default="")) -> str:
        if not auth.configured:
            if allow_no_auth:
                return "default"
            raise HTTPException(503, "gateway auth not configured: set AGENTBASTION_API_KEY "
                                     "or AGENTBASTION_KEYS (or AGENTBASTION_ALLOW_NO_AUTH=1 for dev)")
        tenant = auth.tenant_for(x_api_key)
        if tenant is None and auth.is_admin(x_api_key):
            tenant = "admin"
        if tenant is None:
            raise HTTPException(401, "invalid or missing X-API-Key")
        return tenant

    def require_admin(x_api_key: str = Header(default="")) -> None:
        if not auth.configured and allow_no_auth:
            return
        if auth.is_admin(x_api_key):
            return
        if auth.tenant_for(x_api_key):
            raise HTTPException(403, "admin key required")
        raise HTTPException(401, "invalid or missing admin X-API-Key")

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok", "judge": judge_on, "tool_policy": firewall.tool_policy is not None}

    @app.post("/v1/check/input", response_model=InputVerdict)
    def check_input(body: TextIn, tenant: str = Depends(require_tenant)) -> InputVerdict:
        v = firewall.check_input(body.text, tenant=tenant)
        return InputVerdict(allowed=v.allowed, reason=v.reason, matches=list(v.matches))

    @app.post("/v1/check/output", response_model=OutputVerdict)
    def check_output(body: TextIn, tenant: str = Depends(require_tenant)) -> OutputVerdict:
        redacted, v = firewall.check_output(body.text, tenant=tenant)
        return OutputVerdict(redacted=redacted, findings=list(v.matches))

    @app.post("/v1/check/tool", response_model=ToolVerdict)
    def check_tool(body: ToolIn, tenant: str = Depends(require_tenant)) -> ToolVerdict:
        v = firewall.check_tool(body.name, body.input, tenant=tenant)
        return ToolVerdict(allowed=v.allowed, reason=v.reason)

    @app.get("/v1/stats", dependencies=[Depends(require_admin)])
    def stats_endpoint() -> dict:
        return log_stats(log_path)

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard_page() -> str:
        # Public shell, no data. It prompts for the admin key and fetches
        # /v1/stats with the X-API-Key header - the key never enters the URL.
        return _DASHBOARD_HTML

    return app


_DASHBOARD_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>agentbastion dashboard</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 body{font:14px system-ui,sans-serif;margin:0;background:#0f1216;color:#e6e6e6}
 header{padding:16px 20px;border-bottom:1px solid #232833;display:flex;gap:12px;align-items:center}
 h1{font-size:16px;margin:0;font-weight:600}
 main{padding:20px;display:grid;gap:16px;grid-template-columns:repeat(auto-fill,minmax(320px,1fr))}
 .card{background:#161b22;border:1px solid #232833;border-radius:10px;padding:16px}
 .card h2{font-size:14px;margin:0 0 10px}
 .row{display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid #1c2129}
 .k{color:#9aa4b2}.blk{color:#ff6b6b}.al{color:#5ac8fa}
 input{background:#0f1216;border:1px solid #2a3140;color:#e6e6e6;padding:7px 10px;border-radius:8px}
 button{background:#2d6cdf;border:0;color:#fff;padding:7px 12px;border-radius:8px;cursor:pointer}
 .muted{color:#6b7480}.rb{font-size:12px;color:#c9ced6;padding:2px 0}
</style></head><body>
<header><h1>agentbastion</h1><input id=k type=password placeholder="admin key" size=28>
<button onclick=load()>Load</button><span id=st class=muted></span></header>
<main id=app></main>
<script>
function load(){
 var key=document.getElementById('k').value; try{sessionStorage.setItem('ab_admin',key)}catch(e){}
 document.getElementById('st').textContent='loading...';
 fetch('/v1/stats',{headers:{'X-API-Key':key}}).then(function(r){
   if(!r.ok)throw new Error('HTTP '+r.status); return r.json();}).then(render)
  .catch(function(e){document.getElementById('st').textContent=String(e)});
}
function render(d){
 document.getElementById('st').textContent=d.total+' events';
 var app=document.getElementById('app');app.innerHTML='';
 var tns=d.tenants||{};var names=Object.keys(tns).sort();
 if(!names.length){app.innerHTML='<div class=card><span class=muted>no events yet</span></div>';return;}
 names.forEach(function(n){var t=tns[n];var c=document.createElement('div');c.className='card';
  var h='<h2>'+n+'</h2>';
  h+='<div class=row><span class=k>events</span><span>'+t.events+'</span></div>';
  h+='<div class=row><span class=k blk>blocks</span><span class=blk>'+t.blocks+'</span></div>';
  Object.keys(t.by_stage).forEach(function(s){h+='<div class=row><span class=k>stage: '+s+'</span><span>'+t.by_stage[s]+'</span></div>';});
  Object.keys(t.by_decision).forEach(function(s){h+='<div class=row><span class=k>'+s+'</span><span>'+t.by_decision[s]+'</span></div>';});
  if(t.recent_blocks&&t.recent_blocks.length){h+='<div style="margin-top:8px" class=k>recent blocks</div>';
   t.recent_blocks.forEach(function(b){h+='<div class=rb>['+(b.stage||'')+'] '+(b.detail||'').slice(0,80)+'</div>';});}
  c.innerHTML=h;app.appendChild(c);});
}
try{var s=sessionStorage.getItem('ab_admin');if(s){document.getElementById('k').value=s;load();}}catch(e){}
</script></body></html>"""


app = create_app()


def _run() -> None:
    """Console-script entry: `agentbastion-gateway`. Honors HOST/PORT env."""
    import uvicorn

    uvicorn.run("agentbastion.gateway:app", host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8080")))


if __name__ == "__main__":
    _run()
