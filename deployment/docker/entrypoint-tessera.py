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

    # LLM guardrail (optional)
    guardrail = None
    guardrail_provider = os.environ.get("TESSERA_GUARDRAIL_PROVIDER")
    guardrail_model = os.environ.get("TESSERA_GUARDRAIL_MODEL")

    if guardrail_provider and guardrail_model:
        try:
            from tessera.guardrail import GuardrailCache, LLMGuardrail

            if guardrail_provider == "anthropic":
                import anthropic
                client = anthropic.Anthropic()
            elif guardrail_provider == "openai":
                from openai import OpenAI
                client = OpenAI()
            else:
                client = None
                print(f"Unknown guardrail provider: {guardrail_provider}")

            if client:
                confidence = float(os.environ.get("TESSERA_GUARDRAIL_CONFIDENCE", "0.7"))
                guardrail = LLMGuardrail(
                    client=client,
                    model=guardrail_model,
                    confidence_threshold=confidence,
                    cache=GuardrailCache(),
                )
                print(f"LLM guardrail enabled: {guardrail_provider}/{guardrail_model}")
        except ImportError as e:
            print(f"Guardrail requested but dependency missing: {e}")
        except Exception as e:
            print(f"Guardrail initialization failed: {e}")
    else:
        print("LLM guardrail: disabled (set TESSERA_GUARDRAIL_PROVIDER and TESSERA_GUARDRAIL_MODEL to enable)")

    # Build the FastAPI app
    app = build_app(
        key=signing_key,
        policy=policy,
    )

    # Store guardrail on app state for middleware access
    app.state.guardrail = guardrail

    print(f"Tessera proxy starting on port {port}")
    print(f"Upstream: {upstream_url}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
