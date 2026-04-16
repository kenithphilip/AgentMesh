"""AgentMesh proxy entrypoint for docker-compose."""

from __future__ import annotations

import os

from agentmesh.proxy import MeshProxy


def main() -> None:
    proxy = MeshProxy(
        upstream_url=os.environ.get("TESSERA_UPSTREAM_URL", "http://localhost:3000"),
        policy_path=os.environ.get("TESSERA_POLICY_PATH", "/app/policy.yaml"),
        signing_key=os.environ.get("TESSERA_SIGNING_KEY", "default").encode(),
        principal=os.environ.get("AGENTMESH_PRINCIPAL", "agentmesh-proxy"),
        guardrail_provider=os.environ.get("TESSERA_GUARDRAIL_PROVIDER"),
        guardrail_model=os.environ.get("TESSERA_GUARDRAIL_MODEL"),
    )
    port = int(os.environ.get("TESSERA_PORT", "9090"))
    proxy.run(port=port)


if __name__ == "__main__":
    main()
