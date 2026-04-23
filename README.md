# AgentMesh

[![CI](https://github.com/kenithphilip/AgentMesh/actions/workflows/ci.yml/badge.svg)](https://github.com/kenithphilip/AgentMesh/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-AGPL--3.0-blue)
![python](https://img.shields.io/badge/python-3.12+-blue)
![version](https://img.shields.io/badge/version-0.7.0-blue)

A security mesh for AI agent systems. Sits between your agents and the
tools they call, enforcing taint tracking, content scanning, identity
verification, persistent audit, decision replay, policy synthesis, and
SSRF/URL gating, without changing your agent code.

Built on [Tessera](https://github.com/kenithphilip/Tessera) v0.7.x
(composable primitives library), with support for SPIRE identity,
agentgateway data plane, and OpenTelemetry observability. The hot-path
primitives (policy evaluation, scanners, audit chain, canonical JSON)
are also available as the
[`tessera-rs`](https://pypi.org/project/tessera-rs/) PyO3 wheel for
adapter authors who want the Rust fast path without leaving Python.

## Quickstart

```bash
# Install
pip install agentmesh-mesh tessera-mesh

# Optional: drop in the Rust fast-path for hot primitives
# (compatible with the Python tessera-mesh package, no API changes)
pip install tessera-rs            # latest stable, 0.8.0
pip install tessera-rs==0.9.0a1   # prerelease with OTel-native spans

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

> **Tessera Rust fast-path.** The optional `tessera-rs` wheel exposes
> Rust implementations of `Policy.evaluate`, the heuristic and unicode
> scanners, the hash-chained audit sink, and canonical JSON. The
> Python `tessera-mesh` API stays the same; AgentMesh adapters can
> swap in the Rust implementations where it matters. See
> [Tessera's MIGRATION.md](https://github.com/kenithphilip/Tessera/blob/main/rust/crates/tessera-py/MIGRATION.md)
> for the import map.

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

## 39 HTTP endpoints

Grouped by purpose. OpenAPI docs available at `/docs` when the proxy is
running.

### Health and metrics
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/healthz` | GET | Proxy health and feature flags |
| `/v1/metrics/guardrail` | GET | LLM guardrail call counts and circuit-breaker state |

### Core evaluation
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/evaluate` | POST | Full evaluation pipeline (identity, rate limit, policy, plan, risk, scanners) |
| `/v1/scan` | POST | Quick injection scan (no context update) |
| `/v1/label` | POST | Scan tool output and add to context |
| `/v1/policy` | GET | Current policy requirements |
| `/v1/context` | GET | Context state (segments, trust levels) |
| `/v1/context/split` | GET | Split context into trusted / untrusted halves |
| `/v1/reset` | POST | Clear context for new session |
| `/v1/rate-limit/{id}` | GET | Rate limit status per session |

### Outbound and tool gates
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/ssrf/check` | POST | URL outbound check (SSRF, cloud metadata, schemes) |
| `/v1/url-rules/check` | POST | Static URL allow / deny gate (exact / prefix / glob) |
| `/v1/destructive/check` | POST | Destructive command and SQL pattern check |
| `/v1/supply-chain/check` | POST | Install command typosquat / shadow / off-registry detection |
| `/v1/check-server` | POST | MCP server allowlist check |
| `/v1/check-output` | POST | Output provenance and canary leakage check |
| `/v1/mcp/baseline` | POST | Snapshot tool definitions for drift detection |
| `/v1/mcp/drift` | POST | Check tools against baseline |
| `/v1/tool-shadows` | POST | Cross-server tool name shadowing |
| `/v1/rag/scan` | POST | RAG retrieval chunk scanning |

### Identity and approval
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/heartbeat` | POST | Agent liveness heartbeat |
| `/v1/liveness/{id}` | GET | Agent liveness state |
| `/v1/approve` | POST | Resolve pending human approval |

### Sensitivity high-water mark (IFC)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/sensitivity/classify` | POST | Classify content, optionally observe into HWM |
| `/v1/sensitivity/status` | GET | Current HWM for a trajectory |
| `/v1/sensitivity/status` | DELETE | Reset HWM for a completed trajectory |

### Audit (v0.7.0 hash chain)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/audit/verify` | GET | Walk the JSONL hash chain end-to-end |
| `/v1/audit/cases` | GET | List replayable audit cases with filters |
| `/v1/audit/label` | POST | Attach a ground-truth label to a record |
| `/v1/audit/labels` | GET | Dump the label map |

### Replay and policy synthesis
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/replay/candidates` | GET | List built-in replay candidate policies |
| `/v1/replay/run` | POST | Replay history against a candidate, return stats |
| `/v1/policy/builder/run` | POST | Deterministic policy proposals from labeled history |
| `/v1/policy/builder/llm` | POST | LLM-driven proposals (constrained templates), optionally scored |

### Compliance and distribution
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/audit` | GET | In-memory audit chain validity (legacy) |
| `/v1/audit/sarif` | GET | SARIF 2.1.0 compliance export |
| `/v1/evidence` | GET | Signed evidence bundle |
| `/v1/provenance` | GET | Signed provenance manifest |
| `/v1/xds/snapshot` | GET | xDS-compatible policy snapshot |

## SDK adapters (15 total)

Drop-in adapters that call the proxy instead of running Tessera
in-process. 11 framework adapters, 4 coding-agent hook adapters.

### Framework adapters
| Framework        | Module                       | Class                   |
|------------------|------------------------------|-------------------------|
| LangChain        | `agentmesh.sdk.langchain`    | `MeshCallbackHandler`   |
| OpenAI Agents    | `agentmesh.sdk.openai_agents`| `MeshAgentHooks`        |
| CrewAI           | `agentmesh.sdk.crewai`       | `MeshCrewCallback`      |
| Google ADK       | `agentmesh.sdk.google_adk`   | `MeshADKCallbacks`      |
| LlamaIndex       | `agentmesh.sdk.llamaindex`   | `MeshLlamaIndexHandler` |
| LangGraph        | `agentmesh.sdk.langgraph`    | `MeshLangGraphGuard`    |
| Haystack         | `agentmesh.sdk.haystack`     | `MeshHaystackGuard`     |
| PydanticAI       | `agentmesh.sdk.pydantic_ai`  | `MeshPydanticAIGuard`   |
| NeMo Guardrails  | `agentmesh.sdk.nemo`         | `MeshRailAction`        |
| AgentDojo        | `agentmesh.sdk.agentdojo`    | `MeshToolLabeler` + `MeshToolGuard` |
| Any framework    | `agentmesh.sdk.generic`      | `MeshGuard`             |

### Coding-agent hooks
| Agent       | Module                       | Notes                                |
|-------------|------------------------------|--------------------------------------|
| Claude Code | `agentmesh.sdk.claude_code`  | Stdin JSON, exits 2 on block         |
| Cursor      | `agentmesh.sdk.cursor`       | Defensive field normalization        |
| Copilot CLI | `agentmesh.sdk.copilot`      | Defensive field normalization        |
| Gemini CLI  | `agentmesh.sdk.gemini`       | Defensive field normalization        |

Examples:

```python
# LangChain
from agentmesh.sdk.langchain import MeshCallbackHandler
handler = MeshCallbackHandler(proxy_url="http://localhost:9090")
chain = agent.with_config(callbacks=[handler])

# LlamaIndex
from agentmesh.sdk.llamaindex import MeshLlamaIndexHandler
from llama_index.core.callbacks import CallbackManager
handler = MeshLlamaIndexHandler(proxy_url="http://localhost:9090")
Settings.callback_manager = CallbackManager([handler])

# LangGraph (node functions, not callbacks)
from agentmesh.sdk.langgraph import MeshLangGraphGuard
guard = MeshLangGraphGuard(proxy_url="http://localhost:9090")
graph.add_node("check_tool", guard.check_tool_call)
graph.add_node("label_output", guard.label_tool_output)

# Any framework (manual control)
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
AgentMesh Proxy (39 endpoints)
  |-- Identity (SPIRE JWT-SVID, mTLS, liveness)
  |-- Content scanning (heuristic, directive, intent, unicode, PII)
  |-- URL rules + SSRF guard (deterministic outbound gate)
  |-- Destructive-op + supply-chain pattern checks
  |-- Policy evaluation (taint tracking, CEL rules, plan verification)
  |-- LLM guardrail (circuit-broken, redact-before-judge configurable)
  |-- RAG guard (retrieval chunk scanning, pattern tracking)
  |-- Risk forecasting (salami detection, irreversibility scoring)
  |-- Sensitivity HWM (information flow control)
  |-- Audit (hash-chained JSONL with optional truncation seal)
  |-- Replay + policy builder (deterministic + LLM-driven proposals)
  |-- Compliance (SARIF export, signed evidence, provenance manifests)
  |
  v
Upstream MCP server (agentgateway or direct)
```

## Performance

Measured on Apple M-series, FastAPI TestClient (in-process), 2,000 iterations
per endpoint per config.

| Endpoint | Minimal p50 | Default p50 | Full p50 |
|----------|-------------|-------------|----------|
| `GET /healthz` | 903us | 959us | 965us |
| `POST /v1/evaluate` (clean) | 1.35ms | **1.42ms** | 1.41ms |
| `POST /v1/evaluate` (blocked by taint) | 4.37ms | 4.58ms | 5.27ms |
| `POST /v1/scan` (clean text) | 1.94ms | 2.14ms | 2.20ms |
| `POST /v1/scan` (tainted text) | 8.41ms | 8.55ms | 8.66ms |
| `POST /v1/label` (adds to context) | 3.23ms | 3.28ms | 3.90ms |
| `GET /v1/context` | 3.57ms | 3.98ms | 4.02ms |

Feature overhead is small. Default vs minimal adds **77us p50** to the
evaluate pipeline (+6%). Full config adds 73us (+5%). The scanner cost
on tainted text (8.5ms) is the fixed work of running the sliding-window
injection detector, which is unaffected by feature flags.

Headline: **AgentMesh adds ~1.4ms p50 and ~2.1ms p99 per tool call** at
the default configuration. Reproduce with `python benchmarks/bench_proxy.py`.

## Defense layers

1. **Prompt screening** before context entry (delegated injection defense)
2. **Content scanning** (heuristic, directive, intent, unicode, schema, PII, secrets)
3. **LLM guardrail** with circuit breaker (optional, fires on ambiguous FREE_TEXT; opens after consecutive provider failures, configurable open mode)
4. **Taint tracking** (min_trust floor blocks side-effecting tools)
5. **Value-level taint** (per-argument provenance via DependencyAccumulator)
6. **URL rules gate** (deterministic exact / prefix / glob allow / deny, runs before SSRF and scanners)
7. **SSRF guard** (encoded-IP decoding, DNS-rebinding defense, cloud-metadata rule IDs)
8. **Destructive-op guard** (named patterns: `fs.rm_rf_root`, `sql.drop_table`, `git.push_force_protected`, etc.)
9. **Supply chain scanner** (typosquat, homoglyph, shadow names, off-registry installers)
10. **Read-only guard** (path traversal, mutation detection)
11. **Plan verification** (tool sequence vs user intent)
12. **Risk forecasting** (salami detection, drift, commitment creep, irreversibility scoring)
13. **Toxic flow** (blocks egress when context has both untrusted and sensitive data)
14. **Sensitivity HWM (IFC)** (trajectory-keyed high-water mark, blocks outbound based on max sensitivity ever observed)
15. **RAG guard** (retrieval chunk scanning, poisoned document detection)
16. **Tool shadow detection** (cross-server typosquatting)
17. **MCP baseline drift** (rug-pull detection)
18. **Tool description poisoning scanner**
19. **Canary tokens** (output manipulation confirmation)
20. **Output provenance** (n-gram echo detection, task relevance)
21. **Trust decay** (time-based and anomaly-driven trust degradation)
22. **Cooldown escalation** (adaptive denial response)
23. **Policy invariant** (control-flow bypass detection)
24. **Provenance manifests** (signed segment chains)
25. **Evidence bundles** (signed forensic event export)
26. **SARIF compliance** (security events in standard format)
27. **Side-channel mitigations** (loop guard, structured results)
28. **CEL deny rules** (expression-based policy extension)
29. **Hash-chained audit log** (per-event prev_hash, optional HMAC truncation seal)
30. **Decision replay** (re-run history against any candidate policy, scored against ground-truth labels)
31. **Policy builder** (deterministic and LLM-driven proposals, scored via replay before adoption)

## Tests

```bash
pip install -e '.[dev]' tessera-mesh[agentmesh,cel,sessions]
pytest tests/ -v
# 226 passed in ~1.5s
```

Install from PyPI:

```bash
pip install agentmesh-mesh
```

## Repository structure

```
src/agentmesh/
    proxy.py          Proxy with 39 endpoints (~2,100 lines)
    identity.py       Signing, SPIRE, mTLS, liveness
    transport.py      MCP interceptor, baseline, RAG guard
    exports.py        SARIF, telemetry, evidence, control plane
    client.py         HTTP client for the proxy API
    sdk/              SDK adapters (15 total: 11 frameworks + 4 coding-agent hooks)
tests/                18 test modules, 226 tests
deployment/
    docker/           Docker Compose (SPIRE + agentgateway + proxy + OTel)
examples/
    demo_agent.py     Exercises the proxy endpoints
    demo_tools_server.py  Mock MCP tool server
docs/
    ARCHITECTURE.md   Component contracts
    OPERATOR_GUIDE.md Operations procedures
CHANGELOG.md          Release notes (see also ../docs/CHANGELOG.md in Tessera)
```

## License

AGPL-3.0-or-later.
