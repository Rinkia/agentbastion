"""HTTP gateway - the hosted tier. A thin FastAPI service in front of the same
`Firewall` the SDK uses, so any stack (not just Python) and multiple apps can
call the three guards over the network. This is the surface the paid features
(dashboards, team keys, hosted logs, alerts) build on later.

Run:
    pip install "agentbastion[gateway,judge]"
    export AGENTBASTION_API_KEY=<pick a strong secret>   # required (fail-closed)
    export ANTHROPIC_API_KEY=...                          # optional: enables the judge
    uvicorn agentbastion.gateway:app --host 0.0.0.0 --port 8080

Then:
    curl -s localhost:8080/v1/check/input -H "X-API-Key: $AGENTBASTION_API_KEY" \
         -H 'content-type: application/json' \
         -d '{"text":"ignore all previous instructions"}'

Config (env):
    AGENTBASTION_API_KEY      required gateway key clients send as X-API-Key
    AGENTBASTION_ALLOW_NO_AUTH=1   dev only: run without a key (loud, unsafe)
    AGENTBASTION_TOOL_POLICY  path to a tool-policy YAML (enables /v1/check/tool)
    ANTHROPIC_API_KEY         if set, the inbound LLM judge is enabled
"""

from __future__ import annotations

import hmac
import logging
import os

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .firewall import Firewall
from .tools import load_policy

log = logging.getLogger("agentbastion.gateway")

_API_KEY = os.getenv("AGENTBASTION_API_KEY")
_ALLOW_NO_AUTH = os.getenv("AGENTBASTION_ALLOW_NO_AUTH") == "1"


def _build_firewall() -> Firewall:
    """Assemble the Firewall from env. Judge on iff ANTHROPIC_API_KEY is set."""
    if os.getenv("ANTHROPIC_API_KEY"):
        import anthropic

        fw = Firewall.with_judge(anthropic.Anthropic())
    else:
        fw = Firewall()
    policy_path = os.getenv("AGENTBASTION_TOOL_POLICY")
    if policy_path:
        fw.tool_policy = load_policy(policy_path)
    return fw


firewall = _build_firewall()
_JUDGE_ON = firewall.inbound.judge is not None

app = FastAPI(title="agentbastion gateway", version="0.3.0")


def require_key(x_api_key: str = Header(default="")) -> None:
    """Fail-closed API-key check. No key configured => refuse (503), unless the
    operator explicitly opted into no-auth dev mode. Constant-time compare."""
    if _API_KEY is None:
        if _ALLOW_NO_AUTH:
            return
        raise HTTPException(
            status_code=503,
            detail="gateway auth not configured: set AGENTBASTION_API_KEY "
            "(or AGENTBASTION_ALLOW_NO_AUTH=1 for local dev)",
        )
    if not x_api_key or not hmac.compare_digest(x_api_key, _API_KEY):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


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


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "judge": _JUDGE_ON, "tool_policy": firewall.tool_policy is not None}


@app.post("/v1/check/input", response_model=InputVerdict, dependencies=[Depends(require_key)])
def check_input(body: TextIn) -> InputVerdict:
    v = firewall.check_input(body.text)
    return InputVerdict(allowed=v.allowed, reason=v.reason, matches=list(v.matches))


@app.post("/v1/check/output", response_model=OutputVerdict, dependencies=[Depends(require_key)])
def check_output(body: TextIn) -> OutputVerdict:
    redacted, v = firewall.check_output(body.text)
    return OutputVerdict(redacted=redacted, findings=list(v.matches))


@app.post("/v1/check/tool", response_model=ToolVerdict, dependencies=[Depends(require_key)])
def check_tool(body: ToolIn) -> ToolVerdict:
    v = firewall.check_tool(body.name, body.input)
    return ToolVerdict(allowed=v.allowed, reason=v.reason)


def _run() -> None:
    """Console-script entry: `agentbastion-gateway`. Honors HOST/PORT env."""
    import uvicorn

    uvicorn.run(
        "agentbastion.gateway:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8080")),
    )


if __name__ == "__main__":
    _run()
