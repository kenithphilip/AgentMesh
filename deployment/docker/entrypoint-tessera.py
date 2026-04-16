"""AgentMesh proxy entrypoint for docker-compose."""

from __future__ import annotations

import os

from agentmesh.proxy import MeshProxy


def _bool_env(key: str, default: str = "false") -> bool:
    return os.environ.get(key, default).lower() == "true"


def main() -> None:
    allowlist_raw = os.environ.get("AGENTMESH_MCP_ALLOWLIST", "")
    allowlist = [p.strip() for p in allowlist_raw.split(",") if p.strip()] if allowlist_raw else []

    proxy = MeshProxy(
        upstream_url=os.environ.get("TESSERA_UPSTREAM_URL", "http://localhost:3000"),
        policy_path=os.environ.get("TESSERA_POLICY_PATH", "/app/policy.yaml"),
        signing_key=os.environ.get("TESSERA_SIGNING_KEY", "default").encode(),
        principal=os.environ.get("AGENTMESH_PRINCIPAL", "agentmesh-proxy"),
        guardrail_provider=os.environ.get("TESSERA_GUARDRAIL_PROVIDER"),
        guardrail_model=os.environ.get("TESSERA_GUARDRAIL_MODEL"),
        require_identity=_bool_env("AGENTMESH_REQUIRE_IDENTITY"),
        mcp_allowlist_patterns=allowlist,
        rate_limit_calls=int(os.environ.get("AGENTMESH_RATE_LIMIT", "50")),
        rate_limit_burst=int(os.environ.get("AGENTMESH_BURST_LIMIT", "10")),
        # Tier 2
        enable_prompt_screening=_bool_env("AGENTMESH_PROMPT_SCREENING", "true"),
        enable_secret_redaction=_bool_env("AGENTMESH_SECRET_REDACTION", "true"),
        enable_pii_scanning=_bool_env("AGENTMESH_PII_SCANNING"),
        # Tier 3
        enable_trust_decay=_bool_env("AGENTMESH_TRUST_DECAY"),
        enable_risk_forecasting=_bool_env("AGENTMESH_RISK_FORECASTING", "true"),
        enable_plan_verification=_bool_env("AGENTMESH_PLAN_VERIFICATION", "true"),
        enable_canary_tokens=_bool_env("AGENTMESH_CANARY_TOKENS"),
        cel_rules_path=os.environ.get("AGENTMESH_CEL_RULES_PATH"),
        # Tier A+B
        trust_domain=os.environ.get("AGENTMESH_TRUST_DOMAIN", "agentmesh.local"),
        spire_socket=os.environ.get("SPIFFE_ENDPOINT_SOCKET"),
        enable_rag_guard=_bool_env("AGENTMESH_RAG_GUARD"),
        enable_sarif=_bool_env("AGENTMESH_SARIF", "true"),
        enable_telemetry=_bool_env("AGENTMESH_TELEMETRY"),
    )
    port = int(os.environ.get("TESSERA_PORT", "9090"))
    proxy.run(port=port)


if __name__ == "__main__":
    main()
