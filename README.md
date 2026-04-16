# AgentMesh

[![CI](https://github.com/kenithphilip/AgentMesh/actions/workflows/ci.yml/badge.svg)](https://github.com/kenithphilip/AgentMesh/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-AGPL--3.0-blue)
![python](https://img.shields.io/badge/python-3.12+-blue)

A security mesh for AI agent systems. Sits between your agents and the
tools they call, enforcing taint tracking, content scanning, identity
verification, and compliance audit without changing your agent code.

Built on [Tessera](https://github.com/kenithphilip/Tessera) (51 of 94
modules integrated), with support for SPIRE identity, agentgateway data
plane, and OpenTelemetry observability.

## Quickstart

```bash
# Install
pip install agentmesh tessera-mesh

# Start the demo tools server
python examples/demo_tools_server.py &

# Start the proxy
PYTHONPATH=src python -c "
from agentmesh.proxy import MeshProxy
MeshProxy(signing_key=b'your-key-here-at-least-16-bytes',
          enable_rag_guard=True).run()
"

# Run the demo (in another terminal)
pip install requests
python examples/demo_agent.py
```

## Demo output

```
  [1] Injection Detection and Taint Tracking

  search_hotels: ALLOWED
  read_webpage:  labeled trust=0 (min_trust dropped to 0)
  Scan result:   tainted=True, heuristic=1.00
  send_email:    BLOCKED (context tainted by webpage injection)

  [2] RAG Retrieval Scanning

  Clean chunk:   safe=True, action=allow
  Poison chunk:  safe=False, action=reject

  [3] Tool Shadow Detection

  Shadowed: True
    read_file <-> read_flle  distance=1

  [4] MCP Baseline Drift Detection

  Baseline saved: 2 tools
  Drift detected: True (search: modified)

  [7] Compliance Export (SARIF)

  SARIF version: 2.1.0
  Findings: 11
    [error] tessera/injection-detected
```

## 23 HTTP Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/healthz` | GET | Proxy health and feature flags |
| `/v1/evaluate` | POST | Full evaluation pipeline (identity, rate limit, policy, plan, risk) |
| `/v1/scan` | POST | Quick injection scan (no context update) |
| `/v1/label` | POST | Scan tool output and add to context |
| `/v1/policy` | GET | Current policy requirements |
| `/v1/context` | GET | Context state (segments, trust levels) |
| `/v1/context/split` | GET | Split context into trusted/untrusted halves |
| `/v1/reset` | POST | Clear context for new session |
| `/v1/rate-limit/{id}` | GET | Rate limit status per session |
| `/v1/check-server` | POST | MCP server allowlist check |
| `/v1/check-output` | POST | Output provenance and canary leakage check |
| `/v1/approve` | POST | Resolve pending human approval |
| `/v1/audit` | GET | Audit chain validity |
| `/v1/audit/sarif` | GET | SARIF 2.1.0 compliance export |
| `/v1/evidence` | GET | Signed evidence bundle |
| `/v1/provenance` | GET | Signed provenance manifest |
| `/v1/rag/scan` | POST | RAG retrieval chunk scanning |
| `/v1/mcp/baseline` | POST | Snapshot tool definitions for drift detection |
| `/v1/mcp/drift` | POST | Check tools against baseline |
| `/v1/tool-shadows` | POST | Cross-server tool name shadowing |
| `/v1/heartbeat` | POST | Agent liveness heartbeat |
| `/v1/liveness/{id}` | GET | Agent liveness state |
| `/v1/xds/snapshot` | GET | xDS-compatible policy snapshot |

OpenAPI docs available at `/docs` when the proxy is running.

## Framework SDK

Drop-in adapters that call the proxy instead of running Tessera in-process:

```python
# LangChain
from agentmesh.sdk.langchain import MeshCallbackHandler
handler = MeshCallbackHandler(proxy_url="http://localhost:9090")
chain = agent.with_config(callbacks=[handler])

# OpenAI Agents
from agentmesh.sdk.openai_agents import MeshAgentHooks
agent = Agent(name="travel", hooks=MeshAgentHooks())

# CrewAI
from agentmesh.sdk.crewai import MeshCrewCallback
callback = MeshCrewCallback(proxy_url="http://localhost:9090")

# Google ADK
from agentmesh.sdk.google_adk import MeshADKCallbacks
callbacks = MeshADKCallbacks(proxy_url="http://localhost:9090")

# Any framework
from agentmesh.sdk.generic import MeshGuard
with MeshGuard() as guard:
    guard.start_session("Find hotels and email me the best one")
    ok, reason = guard.before_tool("search_hotels")
    guard.after_tool("search_hotels", results)
```

## Architecture

```
Agent (any framework)
  |
  v
AgentMesh SDK adapter (or direct HTTP)
  |
  v
AgentMesh Proxy (23 endpoints, 51 Tessera modules)
  |-- Identity (SPIRE JWT-SVID, mTLS, liveness)
  |-- Content scanning (heuristic, directive, intent, unicode, PII)
  |-- Policy evaluation (taint tracking, CEL rules, plan verification)
  |-- RAG guard (retrieval chunk scanning, pattern tracking)
  |-- Risk forecasting (salami detection, irreversibility scoring)
  |-- Compliance (SARIF export, signed evidence, audit chain)
  |
  v
Upstream MCP server (agentgateway or direct)
```

## Defense layers

1. **Prompt screening** before context entry (delegated injection defense)
2. **Content scanning** (heuristic, directive, intent, unicode, schema, PII, secrets)
3. **LLM guardrail** (optional, fires only on ambiguous FREE_TEXT)
4. **Taint tracking** (min_trust floor blocks side-effecting tools)
5. **Value-level taint** (per-argument provenance via DependencyAccumulator)
6. **Read-only guard** (path traversal, mutation detection)
7. **Plan verification** (tool sequence vs user intent)
8. **Risk forecasting** (salami detection, drift, commitment creep, irreversibility scoring)
9. **Toxic flow** (blocks egress when context has both untrusted and sensitive data)
10. **RAG guard** (retrieval chunk scanning, poisoned document detection)
11. **Tool shadow detection** (cross-server typosquatting)
12. **MCP baseline drift** (rug-pull detection)
13. **Canary tokens** (output manipulation confirmation)
14. **Output provenance** (n-gram echo detection, task relevance)
15. **Trust decay** (time-based and anomaly-driven trust degradation)
16. **Cooldown escalation** (adaptive denial response)
17. **Policy invariant** (control-flow bypass detection)
18. **Provenance manifests** (signed segment chains)
19. **Evidence bundles** (signed forensic event export)
20. **SARIF compliance** (security events in standard format)
21. **Side-channel mitigations** (loop guard, structured results)
22. **CEL deny rules** (expression-based policy extension)

## Tests

```bash
pip install -e '.[dev]' tessera-mesh[agentmesh,cel,sessions]
pytest tests/ -v
# 106 passed in 5.5s
```

## Repository structure

```
src/agentmesh/
    proxy.py          Proxy with 23 endpoints (1,172 lines)
    identity.py       Signing, SPIRE, mTLS, liveness (141 lines)
    transport.py      MCP interceptor, baseline, RAG guard (173 lines)
    exports.py        SARIF, telemetry, evidence, control plane (148 lines)
    client.py         HTTP client for the proxy API (191 lines)
    sdk/              Framework adapters (LangChain, OpenAI, CrewAI, ADK)
tests/
    test_proxy.py     Core proxy tests (19)
    test_tier2_tier3.py  Production hardening tests (31)
    test_tier_ab.py   Defense-in-depth tests (38)
    test_sdk.py       SDK and client tests (18)
deployment/
    docker/           Docker Compose (SPIRE + agentgateway + proxy + OTel)
examples/
    demo_agent.py     Exercises all 23 endpoints
    demo_tools_server.py  Mock MCP tool server
docs/
    ARCHITECTURE.md   Component contracts
    OPERATOR_GUIDE.md Operations procedures
```

## License

AGPL-3.0-or-later.
