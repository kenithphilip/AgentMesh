"""AgentMesh MCP proxy: transparent security mesh for tool calls.

Extends Tessera's MCPTrustProxy with mesh-specific features:
- Content scanning (heuristic, directive, schema) on all tool outputs
- LLM guardrail integration for ambiguous FREE_TEXT outputs
- Taint-aware context accumulation across the session
- SecurityEvent emission to the mesh observability pipeline
- Health and policy introspection endpoints

The proxy is protocol-transparent: agents see a normal MCP server.
Tool calls are intercepted, scanned, policy-evaluated, and forwarded
to the upstream MCP server. Denied calls return MCP errors.

Architecture:

    Agent (MCP client) --> AgentMesh Proxy --> upstream MCP server
                               |
                        Content scanners
                        Policy evaluation
                        LLM guardrail (optional)
                        Trust labeling
                        SecurityEvent emission

Usage::

    from agentmesh.proxy import MeshProxy

    proxy = MeshProxy(
        upstream_url="http://tools-server:3000/sse",
        policy_path="policy.yaml",
    )
    proxy.run(port=9090)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from tessera.context import Context, LabeledSegment, make_segment
from tessera.labels import Origin, TrustLevel
from tessera.policy import Policy


class _EvalRequest(BaseModel):
    tool_name: str
    args: dict = {}
    user_prompt: str = ""


class _ScanRequest(BaseModel):
    text: str
    tool_name: str = "unknown"


@dataclass
class MeshProxy:
    """AgentMesh MCP proxy with full defense stack.

    Wraps Tessera's policy engine, content scanners, and optional LLM
    guardrail into a single proxy that sits in the MCP tool-call path.

    Args:
        upstream_url: SSE endpoint of the upstream MCP server.
        policy_path: Path to YAML policy file. If None, uses default
            deny-by-default policy.
        signing_key: HMAC key for trust label signing.
        principal: SPIFFE ID or principal name.
        guardrail_provider: "anthropic" or "openai" (optional).
        guardrail_model: Model name for the LLM guardrail (optional).
        injection_threshold: Heuristic score threshold for taint.
    """

    upstream_url: str = "http://localhost:3000"
    policy_path: str | None = None
    signing_key: bytes = b"agentmesh-default-key"
    principal: str = "agentmesh-proxy"
    guardrail_provider: str | None = None
    guardrail_model: str | None = None
    injection_threshold: float = 0.75
    _policy: Policy | None = field(default=None, init=False, repr=False)
    _context: Context = field(default_factory=Context, init=False, repr=False)
    _guardrail: Any = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        # Load policy
        if self.policy_path and os.path.exists(self.policy_path):
            from tessera.ir import compile_policy, from_yaml_path
            self._policy = compile_policy(from_yaml_path(self.policy_path))
        else:
            self._policy = Policy()

        # Initialize guardrail if configured
        if self.guardrail_provider and self.guardrail_model:
            try:
                from tessera.guardrail import GuardrailCache, LLMGuardrail

                if self.guardrail_provider == "anthropic":
                    import anthropic
                    client = anthropic.Anthropic()
                elif self.guardrail_provider == "openai":
                    from openai import OpenAI
                    client = OpenAI()
                else:
                    client = None

                if client:
                    self._guardrail = LLMGuardrail(
                        client=client,
                        model=self.guardrail_model,
                        cache=GuardrailCache(),
                    )
            except ImportError:
                pass

    def evaluate_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        """Evaluate a tool call against the policy.

        Returns (allowed, reason).
        """
        decision = self._policy.evaluate(self._context, tool_name, args=args)
        return decision.allowed, decision.reason or "allowed"

    def scan_and_label(
        self,
        tool_name: str,
        output_text: str,
    ) -> tuple[str, TrustLevel]:
        """Scan tool output and add to context with trust label.

        Returns (text, trust_level).
        """
        from tessera.scanners.directive import scan_directive
        from tessera.scanners.heuristic import injection_scores
        from tessera.scanners.tool_output_schema import (
            ToolOutputKind,
            _resolve_kind,
            scan_tool_output,
        )

        output_kind = _resolve_kind(tool_name)
        is_free_text = output_kind == ToolOutputKind.FREE_TEXT

        h_regex, h_window = injection_scores(output_text)
        d_result = scan_directive(output_text)
        s_result = scan_tool_output(tool_name, output_text)

        if is_free_text:
            override_confirmed = h_regex >= 0.9 and h_window >= 0.85
            is_tainted = d_result.detected or override_confirmed

            # LLM guardrail fallback on uncertain FREE_TEXT
            if not is_tainted and self._guardrail is not None:
                is_tainted = self._guardrail.should_taint(output_text, tool_name)
        else:
            regex_match = h_regex >= 0.9
            window_corroborated = (
                h_window >= self.injection_threshold
                and (d_result.score > 0.2 or s_result.score > 0.3)
            )
            is_tainted = (
                regex_match or d_result.detected
                or s_result.violation or window_corroborated
            )

        trust = TrustLevel.UNTRUSTED if is_tainted else TrustLevel.USER
        origin = Origin.WEB if is_tainted else Origin.TOOL

        seg = make_segment(
            output_text, origin, self.principal, self.signing_key,
            trust_level=trust,
        )
        self._context.add(seg)

        if is_tainted:
            from tessera.events import EventKind, SecurityEvent, emit
            emit(SecurityEvent.now(
                kind=EventKind.CONTENT_INJECTION_DETECTED,
                principal=self.principal,
                detail={
                    "scanner": "mesh_proxy",
                    "tool_name": tool_name,
                    "heuristic_regex": h_regex,
                    "heuristic_window": h_window,
                    "directive_score": d_result.score,
                    "schema_score": s_result.score,
                    "guardrail_used": self._guardrail is not None,
                },
            ))

        return output_text, trust

    def add_user_prompt(self, prompt: str) -> None:
        """Add the user's prompt to the context."""
        seg = make_segment(prompt, Origin.USER, self.principal, self.signing_key)
        self._context.add(seg)

    def reset_context(self) -> None:
        """Reset the context for a new session."""
        self._context = Context()

    @property
    def context(self) -> Context:
        """Current session context."""
        return self._context

    @property
    def policy(self) -> Policy:
        """Current policy."""
        return self._policy

    def build_app(self) -> Any:
        """Build a FastAPI app with mesh proxy endpoints."""
        from fastapi import FastAPI

        app = FastAPI(title="AgentMesh Proxy", version="0.1.0")
        proxy = self  # capture for closures

        @app.get("/healthz")
        def healthz():
            return {
                "status": "ok",
                "service": "agentmesh-proxy",
                "context_segments": len(proxy._context.segments),
                "min_trust": int(proxy._context.min_trust),
                "guardrail_enabled": proxy._guardrail is not None,
            }

        @app.post("/v1/evaluate")
        def api_evaluate(body: _EvalRequest):
            if body.user_prompt and not proxy._context.segments:
                proxy.add_user_prompt(body.user_prompt)
            allowed, reason = proxy.evaluate_tool_call(body.tool_name, body.args)
            return {
                "allowed": allowed,
                "reason": reason,
                "trust_level": int(proxy._context.min_trust),
            }

        @app.post("/v1/scan")
        def api_scan(body: _ScanRequest):
            from tessera.scanners.directive import scan_directive as _scan_d
            from tessera.scanners.heuristic import injection_scores as _scores

            h_r, h_w = _scores(body.text)
            d = _scan_d(body.text)
            tainted = h_r >= 0.9 or d.detected
            return {
                "tainted": tainted,
                "trust_level": 0 if tainted else 100,
                "heuristic_score": max(h_r, h_w),
                "directive_score": d.score,
            }

        @app.post("/v1/label")
        def api_label(body: _ScanRequest):
            _, trust = proxy.scan_and_label(body.tool_name, body.text)
            return {
                "trust_level": int(trust),
                "context_segments": len(proxy._context.segments),
                "min_trust": int(proxy._context.min_trust),
            }

        @app.get("/v1/policy")
        def api_policy():
            reqs = {}
            for key, r in proxy._policy.requirements.items():
                name, _ = key
                reqs[name] = {
                    "required_trust": int(r.required_trust),
                    "side_effects": r.side_effects,
                }
            return {
                "default_trust": int(proxy._policy.default_required_trust),
                "requirements": reqs,
            }

        @app.get("/v1/context")
        def api_context():
            return {
                "segments": len(proxy._context.segments),
                "min_trust": int(proxy._context.min_trust),
                "max_trust": int(proxy._context.max_trust),
            }

        @app.post("/v1/reset")
        def api_reset():
            proxy.reset_context()
            return {"status": "context reset"}

        return app

    def run(self, host: str = "0.0.0.0", port: int = 9090) -> None:
        """Start the proxy server."""
        import uvicorn

        app = self.build_app()
        print(f"AgentMesh proxy starting on {host}:{port}")
        print(f"Upstream: {self.upstream_url}")
        print(f"Guardrail: {'enabled' if self._guardrail else 'disabled'}")
        uvicorn.run(app, host=host, port=port, log_level="info")


def main() -> None:
    """CLI entry point."""
    proxy = MeshProxy(
        upstream_url=os.environ.get("AGENTMESH_UPSTREAM_URL", "http://localhost:3000"),
        policy_path=os.environ.get("AGENTMESH_POLICY_PATH", "policy.yaml"),
        signing_key=os.environ.get("AGENTMESH_SIGNING_KEY", "default").encode(),
        principal=os.environ.get("AGENTMESH_PRINCIPAL", "agentmesh-proxy"),
        guardrail_provider=os.environ.get("AGENTMESH_GUARDRAIL_PROVIDER"),
        guardrail_model=os.environ.get("AGENTMESH_GUARDRAIL_MODEL"),
    )
    port = int(os.environ.get("AGENTMESH_PORT", "9090"))
    proxy.run(port=port)


if __name__ == "__main__":
    main()
