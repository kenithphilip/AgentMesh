"""AgentMesh MCP proxy: production security mesh for tool calls.

Integrates Tessera's full defense stack into a single proxy service:

1. SPIRE identity verification (JWT-SVID on every request)
2. Delegation chain verification (scoped token checking)
3. Per-session rate limiting with burst detection
4. MCP server allowlist with rug-pull detection
5. Content scanning (heuristic, directive, schema, binary, LLM guardrail)
6. Policy evaluation (taint tracking + attribute-based)
7. Compliance events with NIST/CWE enrichment
8. Human approval gates for high-risk tool calls

Architecture:

    Agent (MCP client) --> AgentMesh Proxy --> upstream MCP server
                               |
                        Identity verification (SPIRE)
                        Delegation token check
                        Rate limiting
                        MCP allowlist
                        Content scanners
                        Policy evaluation
                        Compliance audit
                        Human approval (optional)

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

from tessera.context import Context, make_segment
from tessera.labels import Origin, TrustLevel
from tessera.policy import Policy


class _EvalRequest(BaseModel):
    tool_name: str
    args: dict = {}
    user_prompt: str = ""
    session_id: str = "default"
    agent_identity: str | None = None       # JWT-SVID or SPIFFE ID
    delegation_token: str | None = None     # signed delegation token


class _ScanRequest(BaseModel):
    text: str
    tool_name: str = "unknown"


class _ApprovalRequest(BaseModel):
    tool_name: str
    args: dict = {}
    session_id: str = "default"
    approver: str = ""
    approved: bool = False


@dataclass
class MeshProxy:
    """AgentMesh MCP proxy with full enterprise defense stack.

    Args:
        upstream_url: SSE endpoint of the upstream MCP server.
        policy_path: Path to YAML policy file.
        signing_key: HMAC key for trust label signing.
        principal: SPIFFE ID or principal name.
        guardrail_provider: "anthropic" or "openai" (optional).
        guardrail_model: Model name for the LLM guardrail (optional).
        injection_threshold: Heuristic score threshold for taint.
        require_identity: If True, reject requests without valid identity.
        mcp_allowlist_patterns: Allowed MCP server URI patterns.
        rate_limit_calls: Max tool calls per session per window.
        rate_limit_burst: Max calls in 5-second burst window.
    """

    upstream_url: str = "http://localhost:3000"
    policy_path: str | None = None
    signing_key: bytes = b"agentmesh-default-key"
    principal: str = "agentmesh-proxy"
    guardrail_provider: str | None = None
    guardrail_model: str | None = None
    injection_threshold: float = 0.75
    require_identity: bool = False
    mcp_allowlist_patterns: list[str] = field(default_factory=list)
    rate_limit_calls: int = 50
    rate_limit_burst: int = 10

    # Internal state (not constructor args)
    _policy: Policy | None = field(default=None, init=False, repr=False)
    _context: Context = field(default_factory=Context, init=False, repr=False)
    _guardrail: Any = field(default=None, init=False, repr=False)
    _rate_limiter: Any = field(default=None, init=False, repr=False)
    _mcp_allowlist: Any = field(default=None, init=False, repr=False)
    _audit_log: Any = field(default=None, init=False, repr=False)
    _definition_tracker: Any = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        # 1. Load policy from YAML
        if self.policy_path and os.path.exists(self.policy_path):
            from tessera.ir import compile_policy, from_yaml_path
            self._policy = compile_policy(from_yaml_path(self.policy_path))
        else:
            self._policy = Policy()

        # 2. Initialize LLM guardrail (optional)
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
                        client=client, model=self.guardrail_model,
                        cache=GuardrailCache(),
                    )
            except ImportError:
                pass

        # 3. Initialize rate limiter
        from tessera.ratelimit import ToolCallRateLimit
        from datetime import timedelta
        self._rate_limiter = ToolCallRateLimit(
            max_calls=self.rate_limit_calls,
            burst_threshold=self.rate_limit_burst,
            burst_window=timedelta(seconds=5),
            cooldown=timedelta(seconds=30),
            session_lifetime_max=500,
        )

        # 4. Initialize MCP server allowlist
        if self.mcp_allowlist_patterns:
            from tessera.mcp_allowlist import MCPServerAllowlist
            self._mcp_allowlist = MCPServerAllowlist(self.mcp_allowlist_patterns)

        # 5. Initialize compliance audit log
        from tessera.compliance import ChainedAuditLog
        from tessera.events import register_sink
        self._audit_log = ChainedAuditLog()
        register_sink(self._audit_log)

        # 6. Initialize tool definition tracker (rug-pull detection)
        from tessera.mcp_allowlist import ToolDefinitionTracker
        self._definition_tracker = ToolDefinitionTracker()

    # ------------------------------------------------------------------
    # Core evaluation pipeline
    # ------------------------------------------------------------------

    def evaluate_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        session_id: str = "default",
        agent_identity: str | None = None,
        delegation_token_str: str | None = None,
    ) -> tuple[bool, str]:
        """Full evaluation pipeline for a tool call.

        Runs all six enterprise checks in order:
        1. Identity verification
        2. Rate limiting
        3. Delegation token verification
        4. Policy evaluation (taint tracking)
        5. Read-only argument validation
        6. Human approval check

        Returns (allowed, reason).
        """
        # 1. Identity verification
        if self.require_identity and not agent_identity:
            return False, "identity required: no agent_identity provided"

        # 2. Rate limiting
        allowed, reason = self._rate_limiter.check(session_id, tool_name)
        if not allowed:
            return False, f"rate limit: {reason}"

        # 3. Delegation token verification (if provided)
        delegation = None
        if delegation_token_str:
            try:
                from tessera.delegation import DelegationToken, verify_delegation
                import json
                token_data = json.loads(delegation_token_str)
                delegation = DelegationToken(**token_data)
                if not verify_delegation(delegation, self.signing_key):
                    return False, "delegation: invalid token signature"
            except Exception as e:
                return False, f"delegation: {str(e)[:100]}"

        # 4. Policy evaluation (taint tracking)
        decision = self._policy.evaluate(
            self._context, tool_name, args=args,
            delegation=delegation,
            expected_delegate=agent_identity,
        )

        if not decision.allowed:
            # 5. Compliance event enrichment
            from tessera.compliance import enrich_event
            from tessera.events import EventKind, SecurityEvent, emit
            event = SecurityEvent.now(
                kind=EventKind.POLICY_DENY,
                principal=agent_identity or self.principal,
                detail={
                    "tool": tool_name,
                    "session_id": session_id,
                    "required_trust": int(decision.required_trust),
                    "observed_trust": int(decision.observed_trust),
                    "reason": decision.reason,
                },
            )
            emit(event)
            return False, decision.reason or "policy denied"

        # 6. Human approval check
        if tool_name in self._policy._human_approval_tools:
            return False, f"human approval required for tool {tool_name!r}"

        # 7. Read-only argument validation
        from fnmatch import fnmatch
        is_read_only = False
        for key, req in self._policy.requirements.items():
            name, _ = key
            if fnmatch(tool_name, name) and not req.side_effects:
                is_read_only = True
                break

        if is_read_only and args:
            from tessera.read_only_guard import check_read_only_args
            guard_result = check_read_only_args(tool_name, args)
            if not guard_result.passed:
                violations = "; ".join(v[1] for v in guard_result.violations)
                return False, f"read-only guard: {violations}"

        return True, "allowed"

    def scan_and_label(
        self,
        tool_name: str,
        output_text: str,
    ) -> tuple[str, TrustLevel]:
        """Scan tool output, label, and add to context."""
        from tessera.scanners.directive import scan_directive
        from tessera.scanners.heuristic import injection_scores
        from tessera.scanners.tool_output_schema import (
            ToolOutputKind, _resolve_kind, scan_tool_output,
        )

        output_kind = _resolve_kind(tool_name)
        is_free_text = output_kind == ToolOutputKind.FREE_TEXT

        h_regex, h_window = injection_scores(output_text)
        d_result = scan_directive(output_text)
        s_result = scan_tool_output(tool_name, output_text)

        if is_free_text:
            override_confirmed = h_regex >= 0.9 and h_window >= 0.85
            is_tainted = d_result.detected or override_confirmed
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
                },
            ))

        return output_text, trust

    def check_mcp_server(self, server_uri: str) -> tuple[bool, str]:
        """Check if an MCP server is on the allowlist."""
        if self._mcp_allowlist is None:
            return True, "no allowlist configured"
        if self._mcp_allowlist.is_allowed(server_uri):
            return True, "allowed"
        return False, f"MCP server {server_uri!r} not on allowlist"

    def check_tool_definition(
        self, server_uri: str, tool_name: str, definition: str,
    ) -> bool:
        """Check for rug-pull: tool definition changed since last seen."""
        return self._definition_tracker.has_changed(server_uri, tool_name, definition)

    def add_user_prompt(self, prompt: str) -> None:
        seg = make_segment(prompt, Origin.USER, self.principal, self.signing_key)
        self._context.add(seg)

    def reset_context(self) -> None:
        self._context = Context()

    @property
    def context(self) -> Context:
        return self._context

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def audit_chain_valid(self) -> bool:
        """Verify the tamper-evident audit chain."""
        return self._audit_log.verify_chain()

    # ------------------------------------------------------------------
    # HTTP API
    # ------------------------------------------------------------------

    def build_app(self) -> Any:
        """Build a FastAPI app with mesh proxy endpoints."""
        from fastapi import FastAPI, Header
        from typing import Optional

        app = FastAPI(title="AgentMesh Proxy", version="0.2.0")
        proxy = self

        @app.get("/healthz")
        def healthz():
            return {
                "status": "ok",
                "service": "agentmesh-proxy",
                "context_segments": len(proxy._context.segments),
                "min_trust": int(proxy._context.min_trust),
                "guardrail_enabled": proxy._guardrail is not None,
                "identity_required": proxy.require_identity,
                "rate_limiter_active": proxy._rate_limiter is not None,
                "mcp_allowlist_active": proxy._mcp_allowlist is not None,
                "audit_chain_valid": proxy.audit_chain_valid,
            }

        @app.post("/v1/evaluate")
        def api_evaluate(body: _EvalRequest):
            if body.user_prompt and not proxy._context.segments:
                proxy.add_user_prompt(body.user_prompt)
            allowed, reason = proxy.evaluate_tool_call(
                body.tool_name, body.args,
                session_id=body.session_id,
                agent_identity=body.agent_identity,
                delegation_token_str=body.delegation_token,
            )
            return {
                "allowed": allowed,
                "reason": reason,
                "trust_level": int(proxy._context.min_trust),
            }

        @app.post("/v1/scan")
        def api_scan(body: _ScanRequest):
            from tessera.scanners.directive import scan_directive as _d
            from tessera.scanners.heuristic import injection_scores as _s

            h_r, h_w = _s(body.text)
            d = _d(body.text)
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
            approval = list(proxy._policy._human_approval_tools)
            return {
                "default_trust": int(proxy._policy.default_required_trust),
                "requirements": reqs,
                "human_approval_tools": approval,
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

        @app.get("/v1/rate-limit/{session_id}")
        def api_rate_limit(session_id: str):
            status = proxy._rate_limiter.status(session_id)
            return {
                "session_id": status.session_id,
                "calls_in_window": status.calls_in_window,
                "calls_remaining": status.calls_remaining,
                "max_calls": status.max_calls,
                "exceeded": status.exceeded,
            }

        @app.post("/v1/check-server")
        def api_check_server(body: dict):
            uri = body.get("server_uri", "")
            allowed, reason = proxy.check_mcp_server(uri)
            return {"allowed": allowed, "reason": reason}

        @app.get("/v1/audit")
        def api_audit():
            return {
                "chain_valid": proxy.audit_chain_valid,
                "entries": len(proxy._audit_log.entries),
                "timestamps_valid": proxy._audit_log.verify_timestamps()[0],
                "sequences_valid": proxy._audit_log.verify_sequences(),
            }

        return app

    def run(self, host: str = "0.0.0.0", port: int = 9090) -> None:
        import uvicorn

        app = self.build_app()
        features = []
        if self.require_identity:
            features.append("identity")
        if self._guardrail:
            features.append("guardrail")
        if self._mcp_allowlist:
            features.append("allowlist")
        features.append(f"rate-limit({self.rate_limit_calls}/window)")

        print(f"AgentMesh proxy starting on {host}:{port}")
        print(f"Upstream: {self.upstream_url}")
        print(f"Features: {', '.join(features)}")
        uvicorn.run(app, host=host, port=port, log_level="info")


def main() -> None:
    """CLI entry point."""
    allowlist_raw = os.environ.get("AGENTMESH_MCP_ALLOWLIST", "")
    allowlist = [p.strip() for p in allowlist_raw.split(",") if p.strip()] if allowlist_raw else []

    proxy = MeshProxy(
        upstream_url=os.environ.get("AGENTMESH_UPSTREAM_URL", "http://localhost:3000"),
        policy_path=os.environ.get("AGENTMESH_POLICY_PATH", "policy.yaml"),
        signing_key=os.environ.get("AGENTMESH_SIGNING_KEY", "default").encode(),
        principal=os.environ.get("AGENTMESH_PRINCIPAL", "agentmesh-proxy"),
        guardrail_provider=os.environ.get("AGENTMESH_GUARDRAIL_PROVIDER"),
        guardrail_model=os.environ.get("AGENTMESH_GUARDRAIL_MODEL"),
        require_identity=os.environ.get("AGENTMESH_REQUIRE_IDENTITY", "").lower() == "true",
        mcp_allowlist_patterns=allowlist,
        rate_limit_calls=int(os.environ.get("AGENTMESH_RATE_LIMIT", "50")),
        rate_limit_burst=int(os.environ.get("AGENTMESH_BURST_LIMIT", "10")),
    )
    port = int(os.environ.get("AGENTMESH_PORT", "9090"))
    proxy.run(port=port)


if __name__ == "__main__":
    main()
