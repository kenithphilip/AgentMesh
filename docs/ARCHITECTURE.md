# AgentMesh Architecture

## Design Principles

1. **Compose, don't reinvent.** Every component is an existing open-source
   project. AgentMesh's contribution is the wiring and the contracts
   between components, not new implementations of identity, proxy, or
   policy.

2. **Same guarantees at every tier.** Solo, Team, and Enterprise provide
   the same security properties. The difference is operational: where the
   enforcement runs, how identity is bootstrapped, and what observability
   is available.

3. **Tessera is the primitives layer.** AgentMesh depends on Tessera for
   trust labels, taint tracking, policy evaluation, and content scanning.
   AgentMesh adds deployment infrastructure around those primitives.

4. **The data plane is agentgateway.** AgentMesh does not build a new
   proxy. It configures agentgateway with Tessera's security primitives
   via CEL rules and filter plugins.

5. **Identity is SPIFFE/SPIRE.** AgentMesh does not build a new identity
   system. It deploys SPIRE and maps SPIFFE IDs to Tessera's principal
   and delegation models.

---

## Component Contracts

### Contract 1: Agent to Gateway

Every agent connects to the mesh through agentgateway. The gateway is
the enforcement point for tool-level access control, trust label injection,
and delegation verification.

```
Agent (MCP client) --> agentgateway --> MCP server (tools)
                           |
                    Tessera policy evaluation
                    Trust label injection
                    Content scanning
                    Delegation chain verification
```

**Protocol:** MCP over SSE (HTTP) or stdio.

**Agent requirements:**
- Register with the gateway via SPIFFE workload attestation
- Present JWT-SVID on each request
- Accept trust-labeled responses (delimiters are informational,
  not required for correctness)

**Gateway responsibilities:**
- Verify agent identity via SPIFFE
- Evaluate tool calls against Tessera policy
- Inject trust labels on tool outputs
- Run content scanners (heuristic, directive, schema, LLM guardrail)
- Enforce delegation token scope
- Emit SecurityEvents to the observability pipeline

### Contract 2: Gateway to Policy Engine

The gateway delegates policy decisions to an external engine (OPA or Cedar)
for attribute-based rules. Tessera's taint-based policy runs inline in the
gateway for latency-sensitive decisions.

```
Gateway --> Tessera (inline, <50us)
        --> OPA/Cedar (external, <1ms) [optional]
```

**Decision flow:**
1. Tessera taint check (is context tainted? is tool side-effecting?)
2. If Tessera allows, check OPA/Cedar for attribute rules
3. If both allow, execute the tool call

**Policy input:** Tessera's `PolicyInput` (tool, args, principal,
trust levels, delegation) is sent to OPA/Cedar as JSON. The external
engine returns allow/deny with an optional reason.

### Contract 3: Gateway to SPIRE

SPIRE provides workload identity. Each agent and each tool server gets a
SPIFFE ID. The gateway verifies these identities on every request.

```
SPIRE server
    |
    +--> SPIRE agent (node attestation)
    |       |
    |       +--> Agent workload (JWT-SVID)
    |       +--> Tool server workload (JWT-SVID)
    |
    +--> Gateway (JWKS trust bundle for verification)
```

**Identity format:** `spiffe://mesh.example.com/agent/<name>`
**Delegation format:** Tessera `DelegationToken` signed with the
delegator's key, scoped to specific tool actions.

### Contract 4: Observability Pipeline

SecurityEvents flow from the gateway to an OTel collector, which routes
them to both a tracing backend (Jaeger/Tempo) and a SIEM (Splunk/Elastic).

```
Gateway --> OTel Collector --> Tracing backend (spans)
                           --> SIEM (security events)
                           --> Alerting (PagerDuty/Slack)
```

**Event types to alert on:**
- `POLICY_DENY`: tool call blocked by taint tracking
- `CONTENT_INJECTION_DETECTED`: scanner found injection in tool output
- `GUARDRAIL_DECISION`: LLM guardrail fired and classified
- `WORKER_SCHEMA_VIOLATION`: dual-LLM bypass attempt
- `LABEL_VERIFY_FAILURE`: tampered or forged trust label
- `DELEGATION_VERIFY_FAILURE`: invalid or expired delegation

### Contract 5: Content Scanning Pipeline

Tool outputs pass through a scanning pipeline before reaching the agent.
The pipeline runs inline in the gateway for deterministic checks and
delegates to a guardrail service for semantic classification.

```
Tool output --> Binary scanner (PDF, image, MIME)
           --> Heuristic scanner (override patterns)
           --> Directive scanner (model-targeting)
           --> Schema enforcement (structural shape)
           --> [Optional] LLM guardrail service
           --> Trust label assignment
           --> Forwarded to agent
```

**Latency budget:** <2ms for deterministic scanners. LLM guardrail adds
one model call (~200ms) but only fires on ambiguous FREE_TEXT outputs
where deterministic scanners are uncertain.

---

## Deployment Architecture by Tier

### Solo (in-process)

```
Your Python process
  +-- AgentMesh SDK
  |     +-- Tessera (embedded)
  |     +-- Policy (WASM-compiled Rego, in-process)
  |     +-- OTel auto-instrumentation
  +-- Your agent framework (LangChain, OpenAI, etc.)
```

No external services. Everything runs in the agent's process. Identity
is HMAC-based (symmetric key). Policy is evaluated inline. Events are
emitted to stdout or a webhook.

### Team (Docker Compose)

```
docker compose up
  +-- agentgateway (MCP/A2A proxy)
  +-- spire-server (identity)
  +-- spire-agent (workload attestation)
  +-- otel-collector (observability)
  +-- [optional] opa (external policy)
  +-- [optional] guardrail-service (LLM classifier)
```

Agents connect to the gateway instead of directly to tool servers. The
gateway handles policy, scanning, and trust labeling. SPIRE provides
workload identity. OTel collects events.

### Enterprise (Kubernetes + Helm)

```
helm install agentmesh ./charts/agentmesh
  +-- agentgateway (DaemonSet or Deployment)
  +-- spire-server (StatefulSet)
  +-- spire-agent (DaemonSet)
  +-- otel-collector (Deployment)
  +-- opa (Deployment)
  +-- guardrail-service (Deployment, autoscaled)
  +-- tessera-control-plane (Deployment, optional)
```

Adds mTLS between all components, horizontal scaling of the guardrail
service, centralized policy management via the control plane, and
Kubernetes-native workload attestation.

---

## Roadmap

| Phase | Deliverable | Status |
|-------|------------|--------|
| 0 | Architecture spec and component contracts | Current |
| 1 | Team tier docker-compose (agentgateway + SPIRE + Tessera) | Next |
| 2 | Solo tier SDK (embedded, zero infrastructure) | Planned |
| 3 | Enterprise tier Helm charts | Planned |
| 4 | Upstream PR to agentgateway (Tessera filter plugins) | Planned |
