"""Tessera proxy entrypoint for the AgentMesh docker-compose deployment.

Loads policy from YAML, configures the proxy with SPIFFE identity
(when available), and starts the FastAPI server.
"""

from __future__ import annotations

import os
import sys


def main() -> None:
    import uvicorn

    from tessera.ir import compile_policy, from_yaml_path
    from tessera.proxy import build_app

    policy_path = os.environ.get("TESSERA_POLICY_PATH", "/app/policy.yaml")
    upstream_url = os.environ.get("TESSERA_UPSTREAM_URL", "http://localhost:8080")
    signing_key = os.environ.get("TESSERA_SIGNING_KEY", "default-key").encode()
    port = int(os.environ.get("TESSERA_PORT", "9090"))

    # Load policy from YAML
    if os.path.exists(policy_path):
        policy = compile_policy(from_yaml_path(policy_path))
        print(f"Loaded policy from {policy_path}")
    else:
        from tessera.policy import Policy
        policy = Policy()
        print("No policy file found, using default deny-by-default policy")

    # Build the FastAPI app
    app = build_app(
        key=signing_key,
        policy=policy,
    )

    print(f"Tessera proxy starting on port {port}")
    print(f"Upstream: {upstream_url}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
