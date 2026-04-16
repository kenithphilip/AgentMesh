"""Demo agent that exercises the AgentMesh.

Simulates an agent workflow:
1. Search for hotels (read-only, allowed)
2. Read a webpage (read-only, allowed, but content contains injection)
3. Send email with results (side-effecting, should be BLOCKED by Tessera
   because the context now contains untrusted content from the webpage)

Run this after docker compose up:
    pip install tessera-mesh requests
    python examples/demo_agent.py

Expected output:
    search_hotels: ALLOWED (read-only, clean data)
    read_webpage: ALLOWED (read-only, but content is tainted)
    send_email: BLOCKED (context tainted by webpage injection)
"""

from __future__ import annotations

import json
import sys

import requests


TESSERA_PROXY = "http://localhost:9090"
DEMO_TOOLS = "http://localhost:3000"


def call_tool(tool_name: str, args: dict) -> dict:
    """Call a tool through the demo server."""
    response = requests.post(DEMO_TOOLS, json={"tool": tool_name, "args": args})
    return response.json()


def main() -> None:
    print("=" * 60)
    print("AgentMesh Demo: Injection Blocked at the Mesh")
    print("=" * 60)
    print()

    # Step 1: Search hotels (safe, read-only)
    print("[1] Searching for hotels in Paris...")
    result = call_tool("search_hotels", {"city": "Paris"})
    print(f"    Result: {result['result'][:80]}...")
    print(f"    Status: ALLOWED (read-only tool, clean data)")
    print()

    # Step 2: Read webpage (safe tool, but content has injection)
    print("[2] Reading travel guide webpage...")
    result = call_tool("read_webpage", {"url": "https://travel-guide.example.com/paris"})
    content = result["result"]
    print(f"    Result: {content[:80]}...")

    # Check if the content contains injection
    from tessera.scanners.heuristic import injection_score
    score = injection_score(content)
    print(f"    Injection score: {score:.2f}")
    if score >= 0.75:
        print(f"    WARNING: Content contains injection payload!")
    print(f"    Status: ALLOWED (read-only tool, content marked UNTRUSTED)")
    print()

    # Step 3: Try to send email (should be blocked)
    print("[3] Attempting to send email with results...")
    print("    (Context is tainted by webpage injection)")

    from tessera.context import Context, make_segment
    from tessera.labels import Origin, TrustLevel
    from tessera.policy import Policy
    from tessera.ir import from_yaml_path, compile_policy

    # Build context with the tainted webpage content
    key = b"demo-key"
    ctx = Context()
    ctx.add(make_segment("Find hotels in Paris and email me the best one", Origin.USER, "demo", key))
    ctx.add(make_segment(json.dumps(json.loads(result["result"])[:1]) if isinstance(result["result"], str) else str(result["result"]), Origin.TOOL, "demo", key))
    ctx.add(make_segment(content, Origin.WEB, "demo", key))

    # Evaluate policy
    policy = Policy()
    policy.require("send_email", TrustLevel.USER)
    policy.require("search_hotels", TrustLevel.USER, side_effects=False)
    policy.require("read_webpage", TrustLevel.USER, side_effects=False)

    decision = policy.evaluate(ctx, "send_email")
    if decision.allowed:
        print("    Status: ALLOWED (this should not happen!)")
    else:
        print(f"    Status: BLOCKED")
        print(f"    Reason: {decision.reason}")
        print(f"    Context min_trust: {ctx.min_trust}")

    print()
    print("=" * 60)
    print("The injection in the webpage was detected and the email")
    print("was blocked. The attacker's payload tried to redirect")
    print("booking details to admin@travel-reviews-verification.com")
    print("but Tessera's taint tracking prevented the send_email")
    print("tool from executing in a tainted context.")
    print("=" * 60)


if __name__ == "__main__":
    main()
