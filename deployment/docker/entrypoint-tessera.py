"""Tessera mesh proxy: policy enforcement and content scanning.

Provides HTTP endpoints for agents to check tool calls against
Tessera's policy engine and scan tool outputs for injection.
This is the mesh-native proxy, not the OpenAI-compatible sidecar.
"""

from __future__ import annotations

import json
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Tessera Mesh Proxy", version="0.3.0")


class ToolCallRequest(BaseModel):
    tool_name: str
    args: dict = {}
    session_id: str = "default"
    user_prompt: str = ""


class ScanRequest(BaseModel):
    text: str
    tool_name: str = "unknown"


class DecisionResponse(BaseModel):
    allowed: bool
    reason: str
    trust_level: int


class ScanResponse(BaseModel):
    tainted: bool
    heuristic_score: float
    directive_score: float
    category: str


# Load policy at startup
_policy = None
_guardrail = None


def _get_policy():
    global _policy
    if _policy is None:
        policy_path = os.environ.get("TESSERA_POLICY_PATH", "/app/policy.yaml")
        if os.path.exists(policy_path):
            from tessera.ir import compile_policy, from_yaml_path
            _policy = compile_policy(from_yaml_path(policy_path))
        else:
            from tessera.policy import Policy
            _policy = Policy()
    return _policy


@app.get("/healthz")
def health():
    return {"status": "ok", "service": "tessera-mesh-proxy"}


@app.post("/v1/evaluate", response_model=DecisionResponse)
def evaluate_tool_call(req: ToolCallRequest):
    """Evaluate a tool call against the Tessera policy."""
    from tessera.context import Context, make_segment
    from tessera.labels import Origin, TrustLevel

    key = os.environ.get("TESSERA_SIGNING_KEY", "default").encode()
    policy = _get_policy()

    ctx = Context()
    if req.user_prompt:
        ctx.add(make_segment(req.user_prompt, Origin.USER, "mesh", key))

    decision = policy.evaluate(ctx, req.tool_name, args=req.args)

    return DecisionResponse(
        allowed=decision.allowed,
        reason=decision.reason or "allowed",
        trust_level=int(ctx.min_trust),
    )


@app.post("/v1/scan", response_model=ScanResponse)
def scan_tool_output(req: ScanRequest):
    """Scan tool output for injection content."""
    from tessera.scanners.directive import scan_directive
    from tessera.scanners.heuristic import injection_scores

    h_regex, h_window = injection_scores(req.text)
    d_result = scan_directive(req.text)

    tainted = h_regex >= 0.9 or d_result.detected
    category = "clean"
    if d_result.detected:
        category = "directive"
    elif h_regex >= 0.9:
        category = "override"

    return ScanResponse(
        tainted=tainted,
        heuristic_score=max(h_regex, h_window),
        directive_score=d_result.score,
        category=category,
    )


@app.get("/v1/policy")
def get_policy_summary():
    """Return the current policy configuration."""
    policy = _get_policy()
    reqs = {}
    for key, req in policy.requirements.items():
        name, rtype = key
        reqs[name] = {
            "required_trust": int(req.required_trust),
            "side_effects": req.side_effects,
        }
    return {
        "default_trust": int(policy.default_required_trust),
        "requirements": reqs,
    }


if __name__ == "__main__":
    import uvicorn

    # Configure guardrail if env vars are set
    provider = os.environ.get("TESSERA_GUARDRAIL_PROVIDER")
    model = os.environ.get("TESSERA_GUARDRAIL_MODEL")
    if provider and model:
        print(f"LLM guardrail: {provider}/{model}")
    else:
        print("LLM guardrail: disabled")

    port = int(os.environ.get("TESSERA_PORT", "9090"))
    print(f"Tessera mesh proxy starting on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
