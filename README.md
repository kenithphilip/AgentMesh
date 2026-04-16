# AgentMesh

**An open security mesh for AI agent systems, composing Tessera, agentgateway, and SPIRE into a deployable defense layer.**

![status](https://img.shields.io/badge/status-architecture-yellow)
![license](https://img.shields.io/badge/license-AGPL--3.0-blue)

AgentMesh is to AI agents what Istio is to microservices: a security and
observability layer that sits between your agents and the tools they call,
enforcing identity, authorization, taint tracking, and audit without
changing your agent's code.

## Architecture

AgentMesh composes four open-source primitives:

| Layer | Component | What it does |
|-------|-----------|-------------|
| **Primitives** | [Tessera](https://github.com/kenithphilip/Tessera) | Signed trust labels, taint tracking, policy engine, LLM guardrail, content scanners |
| **Data plane** | [agentgateway](https://github.com/solo-io/agentgateway) | MCP/A2A proxy with CEL-based routing and tool-level access control |
| **Identity** | [SPIRE](https://github.com/spiffe/spire) | Workload identity via SPIFFE, JWT-SVID issuance, trust domain management |
| **Policy** | [OPA](https://github.com/open-policy-agent/opa) / [Cedar](https://github.com/cedar-policy/cedar) | Attribute-based policy evaluation (complements Tessera's taint-based policy) |

AgentMesh does not replace these projects. It wires them together into a
coherent security posture and fills the gaps between them.

## Three Deployment Tiers

| Tier | Target | Infrastructure | Overhead |
|------|--------|---------------|----------|
| **Solo** | Single developer | None (embedded library) | < 0.5ms |
| **Team** | Small team, shared agents | Docker Compose | < 5ms |
| **Enterprise** | Production, multi-tenant | Kubernetes + Helm | < 15ms |

Every tier provides the same security guarantees. The difference is
operational: Solo runs in-process, Team adds a gateway proxy, Enterprise
adds mTLS, sandboxing, and centralized policy.

## What AgentMesh adds over Tessera alone

Tessera is a library. You integrate it into your agent code. AgentMesh is
infrastructure. You deploy it alongside your agents.

| Capability | Tessera | AgentMesh |
|-----------|---------|-----------|
| Trust labels on context segments | Library API | Automatic at the proxy |
| Policy enforcement | Per-adapter, in-process | Centralized, gateway-enforced |
| Workload identity | JWT-SVID helpers | Full SPIRE deployment |
| Tool-level access control | Policy.require() | agentgateway CEL rules |
| Multi-agent delegation | DelegationToken API | Gateway-enforced delegation chains |
| Observability | SecurityEvent sinks | Full OTel pipeline with SIEM routing |
| Content scanning | Scanner registry | Inline at the proxy, before the agent sees it |
| LLM guardrail | Optional per-adapter | Centralized guardrail service |

## Current Status

AgentMesh is in the architecture phase. The spec is written
(`specs/AGENTMESH_V2_SPEC.md`), the component contracts are defined,
and Tessera (the primitives library) is proven at v0.3.0 with 100% APR
on AgentDojo and 1173 passing tests.

The next milestone is the Team tier: a docker-compose that wires Tessera +
agentgateway + SPIRE into a running mesh.

## Repository Structure

```
specs/           Architecture specifications
docs/            Design documents and component contracts
deployment/
  docker/        Docker Compose for Team tier
  helm/          Helm charts for Enterprise tier
  spire/         SPIRE server and agent configuration
src/agentmesh/   Python SDK and CLI
examples/        Runnable demos
```

## License

AGPL-3.0-or-later. Same as Tessera.
