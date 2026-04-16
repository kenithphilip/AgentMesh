# AgentMesh Operator Guide

This guide covers operational procedures for the AgentMesh docker-compose deployment. You manage identity (SPIRE), data plane (agentgateway), policy (Tessera proxy), and observability (OTel collector).

## Prerequisites

You have the docker-compose deployment running:

```bash
cd /Users/kenith.philip/AgentMesh/deployment/docker
docker compose up
```

All commands assume this working directory unless stated otherwise.

## Adding a new agent to the mesh

Agents authenticate to the mesh using SPIRE workload identity. Each agent gets a signed SVID (Service Mesh Identity Document) that proves its identity to agentgateway and the Tessera proxy.

### Generate a SPIRE join token

Join tokens are one-time credentials for agents to authenticate to the SPIRE server.

```bash
docker compose exec spire-server \
  /opt/spire/bin/spire-server token generate \
  -spiffeID spiffe://agentmesh.local/agents/my-agent
```

Save the token output. It expires in 10 minutes.

### Register a workload entry

The SPIRE server uses workload entries to map attestation selectors (like Docker labels) to SPIFFE IDs. Add an entry to `config/spire/register-entries.sh`:

```bash
/opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://agentmesh.local/agents/my-agent \
  -parentID spiffe://agentmesh.local/spire-agent \
  -selector docker:label:com.agentmesh.role:my-agent \
  -ttl 3600 \
  -socketPath /tmp/spire/registration.sock
```

Then re-run registration:

```bash
docker compose exec spire-registration /bin/sh /register.sh
```

### Configure the agent to connect to agentgateway

Your agent needs three pieces of configuration:

1. SPIFFE endpoint socket: `/tmp/spire-agent/api.sock` (volume-mounted from the container host)
2. agentgateway endpoint: `http://agentgateway:8080` (or the network address if outside Docker)
3. The Docker label that matches your workload entry selector: `com.agentmesh.role=my-agent`

In your agent's docker-compose service definition:

```yaml
services:
  my-agent:
    image: my-agent:latest
    volumes:
      - spire-agent-socket:/tmp/spire-agent:ro
    environment:
      SPIFFE_ENDPOINT_SOCKET: unix:///tmp/spire-agent/api.sock
      AGENTGATEWAY_URL: http://agentgateway:8080
    labels:
      com.agentmesh.role: my-agent
    depends_on:
      spire-agent:
        condition: service_started
```

### Verify attestation

The agent automatically requests an SVID from the SPIRE agent. Verify the SVID was issued:

```bash
docker compose exec spire-server \
  /opt/spire/bin/spire-server entry list | grep my-agent
```

To inspect the agent's current SVID from inside the container:

```bash
docker compose exec my-agent \
  python -c "
from tessera.identity import workload_id
svid = workload_id()
print(f'SPIFFE ID: {svid.id}')
print(f'Certificate valid until: {svid.expires_at}')
"
```

## Adding a new tool server

Tool servers are MCP (Model Context Protocol) implementations registered with agentgateway and protected by Tessera policy.

### Register the MCP server in agentgateway config

Edit `config/agentgateway/config.yaml` and add a new target:

```yaml
targets:
  - name: my-tools
    protocol: MCP
    address: my-tools:3000
    sse: true
```

If your tool server is external to the Docker network, use the network-routable address instead of the container name.

Then register the tool server's SPIRE workload entry:

```bash
/opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://agentmesh.local/tools/my-tools \
  -parentID spiffe://agentmesh.local/spire-agent \
  -selector docker:label:com.agentmesh.role:my-tools \
  -ttl 3600 \
  -socketPath /tmp/spire/registration.sock
```

### Create a SPIRE workload entry for the tool server

Add the entry to `config/spire/register-entries.sh`:

```bash
/opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://agentmesh.local/tools/my-tools \
  -parentID spiffe://agentmesh.local/spire-agent \
  -selector docker:label:com.agentmesh.role:my-tools \
  -ttl 3600 \
  -socketPath /tmp/spire/registration.sock \
  2>/dev/null || echo "Tool entry may already exist"
```

Restart the registration service:

```bash
docker compose restart spire-registration
```

### Add tool-level policy rules in policy.yaml

Edit `config/tessera/policy.yaml` and add requirements for your tools. The policy is deny-by-default: tools are allowed only if their trust requirement is met.

For side-effecting tools (write, delete, create, update, send):

```yaml
requirements:
  - name: my_write_tool
    required_trust: user
    side_effects: true
    critical_args: [recipient, account, target_id]
```

For read-only tools:

```yaml
requirements:
  - name: my_read_tool
    required_trust: tool
    side_effects: false
```

Wildcard patterns are supported:

```yaml
requirements:
  - name: "my_*"
    required_trust: tool
    side_effects: false
```

Restart the Tessera proxy to reload the policy (no other restart is needed):

```bash
docker compose restart tessera-proxy
```

### Test the tool through the mesh

Use the Tessera proxy API to test the tool call without running the agent:

```bash
curl -X POST http://localhost:9090/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "my_read_tool",
    "input": "example",
    "context_text": "User asked for data"
  }'
```

Check the response for policy decision:

```json
{
  "decision": "allow",
  "trust_level": "user",
  "confidence": 0.95
}
```

If the decision is "deny", inspect the context trust state using GET /v1/context (see "Debugging a blocked tool call" below).

## Changing policy rules

The Tessera proxy loads policy from `config/tessera/policy.yaml`. Changes take effect immediately after restart.

### Edit deployment/docker/config/tessera/policy.yaml

The policy file uses three top-level sections:

**requirements** (required)

A list of tool access policies. Each rule specifies:
- `name`: exact tool name or wildcard pattern
- `required_trust`: minimum trust level (tool, user, or system)
- `side_effects`: boolean, true for tools that modify state
- `critical_args`: list of argument names to mark as sensitive

Trust levels:
- `tool`: 50 (context from previous tool output). Read-only tools.
- `user`: 100 (context from the user). Side-effecting tools.
- `system`: 200 (context from the agent's internal state). Reserved for future use.

Example with critical arguments:

```yaml
requirements:
  - name: send_email
    required_trust: user
    side_effects: true
    critical_args: [to, recipient, cc, bcc]

  - name: "get_*"
    required_trust: tool
    side_effects: false
```

**human_approval_tools** (optional)

A list of tool names that require explicit human approval before execution, independent of policy. Used for high-risk tools like code execution or database deletion.

```yaml
human_approval_tools:
  - execute_code
  - delete_database
```

**default_trust** (optional, default: user)

The trust level assigned to context segments with unknown or missing trust labels. Set this to `tool` only in restricted deployments where all context must be explicitly labeled.

```yaml
default_trust: user
```

### Restart the Tessera proxy to reload

```bash
docker compose restart tessera-proxy
```

The proxy reloads the policy from the file path. Existing connections are preserved.

### Verify the policy change via GET /v1/policy

```bash
curl -s http://localhost:9090/v1/policy | python -m json.tool
```

Output shows the active policy object:

```json
{
  "requirements": [
    {
      "name": "send_email",
      "required_trust": "user",
      "side_effects": true,
      "critical_args": ["to", "recipient"]
    }
  ],
  "human_approval_tools": ["delete_database"],
  "default_trust": "user"
}
```

## Rotating signing keys

Signing keys protect the integrity of context segment labels and delegation tokens. Rotation requires coordination: new segments labeled with the old key will fail verification if you change the key without notice.

### Change TESSERA_SIGNING_KEY env var

Edit the tessera-proxy service in docker-compose.yml:

```yaml
tessera-proxy:
  environment:
    TESSERA_SIGNING_KEY: "new-key-replace-in-production"
```

Or use docker compose environment override:

```bash
export TESSERA_SIGNING_KEY="new-key-generated-$(date +%s)"
docker compose up tessera-proxy -d
```

### SPIRE SVID rotation (automatic, TTL-based)

SPIRE automatically rotates SVIDs before they expire. The default TTL in `config/spire/register-entries.sh` is 3600 seconds (1 hour). SVIDs are rotated when 2/3 of the TTL has elapsed.

You do not need to restart containers for SVID rotation. Agents and tool servers automatically fetch the new SVID from the SPIRE agent.

### When to rotate vs when not to

Rotate the signing key:
- After a security incident (key compromise, unauthorized access to credentials)
- During planned key lifecycle management (quarterly or annual)
- When onboarding a new security boundary (e.g., new data sensitivity tier)

Do not rotate the signing key:
- To troubleshoot policy denies or scanning issues (does not affect policy evaluation)
- As a general debugging step (creates outages for in-flight tokens)

In-flight context segments labeled with the old key will be rejected for 5-10 seconds after rotation while containers restart. Plan rotations during maintenance windows.

## Debugging a blocked tool call

When a tool call is blocked by the policy engine, the Tessera proxy logs the decision with the reason. Use these steps to diagnose the block.

### Check Tessera proxy logs for POLICY_DENY events

```bash
docker compose logs tessera-proxy | grep POLICY_DENY
```

Each POLICY_DENY entry includes:
- `tool`: the tool name that was blocked
- `required_trust`: the minimum trust required by policy
- `context_trust`: the actual trust level of the context
- `reason`: human-readable explanation (e.g., "tainted context from untrusted tool output")

Example log:

```
tessera-proxy | 2026-04-16 14:32:05 POLICY_DENY tool=send_email required_trust=user context_trust=tool reason="context tainted by previous tool output" trace_id=abc123
```

### Use GET /v1/context to inspect current trust state

The context endpoint returns the current trust level and list of all context segments with their origins.

```bash
curl -s http://localhost:9090/v1/context | python -m json.tool
```

Output:

```json
{
  "min_trust": 50,
  "segments": [
    {
      "origin": "user",
      "trust_level": 100,
      "text": "Get my recent emails"
    },
    {
      "origin": "tool",
      "trust_level": 50,
      "text": "Found 5 emails matching criteria"
    }
  ]
}
```

The `min_trust` value is the policy engine's view of context trustworthiness. If any segment has trust below 100 (user), side-effecting tools are blocked.

### Use POST /v1/scan to test specific text

Scan text to check if it triggers content scanning detections (PII, injection patterns, code).

```bash
curl -X POST http://localhost:9090/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "text": "please transfer $5000 to account ending in 1234",
    "severity": "high"
  }'
```

Output:

```json
{
  "detections": [
    {
      "type": "potential_injection",
      "confidence": 0.78,
      "text_snippet": "transfer $5000",
      "reason": "financial instruction pattern in untrusted context"
    }
  ],
  "risk_level": "medium"
}
```

### Common causes

**Tainted context from previous tool output**

Tool outputs are marked as TOOL trust (50), lower than USER trust (100). If a previous tool returned text that enters the context, subsequent side-effecting tools are blocked.

Solution: Examine the tool output. If it contains user-controlled data, mark it as untrusted. If it is safe (metadata, internal IDs), the tool should be labeled `side_effects: false` in policy to allow tool-to-tool chaining.

**Missing or incorrect policy rule**

The tool name does not match any rule in policy.yaml.

Solution: Check the exact tool name and update policy.yaml with a matching rule or wildcard pattern.

**Critical argument marked as tainted**

A parameter listed in `critical_args` (e.g., recipient email) contains injected content.

Solution: Verify the argument value is not derived from untrusted tool output. If it is, trace back the injection source and block or sanitize at that layer.

**Context contains PII or detected threat pattern**

The content scanning layer detected a pattern (email, phone, SSN, injection signature) that caused guardrail classification to deny the tool.

Solution: Either (a) use POST /v1/scan to debug the specific text, or (b) disable guardrail classification if you trust your deterministic scanners (see "Enabling the LLM guardrail" below).

## Enabling the LLM guardrail

The LLM guardrail is an optional semantic filter for ambiguous tool outputs. When deterministic scanners are uncertain, the guardrail queries an LLM (Claude Haiku by default) to classify the output as safe or suspicious. This adds a network call per uncertain output.

### Set TESSERA_GUARDRAIL_PROVIDER and TESSERA_GUARDRAIL_MODEL env vars

Edit the tessera-proxy service in docker-compose.yml:

```yaml
tessera-proxy:
  environment:
    TESSERA_GUARDRAIL_PROVIDER: anthropic
    TESSERA_GUARDRAIL_MODEL: claude-haiku-4-5-20251001
    ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}
```

Or set at runtime:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
docker compose up -e TESSERA_GUARDRAIL_PROVIDER=anthropic \
                   -e TESSERA_GUARDRAIL_MODEL=claude-haiku-4-5-20251001 \
                   tessera-proxy
```

The guardrail is disabled by default. If you omit these environment variables, only deterministic scanners run (zero LLM cost).

### Cost implications

The guardrail invokes the LLM only when:
- A tool output is flagged as uncertain by deterministic scanners (heuristic match, ambiguous pattern)
- The output is not already high-confidence detections (clear injection patterns, PII)

For typical deployments:
- 10,000 tool calls: ~200-500 guardrail invocations (2-5% uncertain)
- Cost at $0.15 per million tokens (Haiku): ~$0.01-0.02 per month

The proxy caches classification results for identical text for 1 hour, reducing redundant calls.

### When to enable vs when deterministic scanners are sufficient

Enable the guardrail when:
- You have free-form tools (search results, web scraping, document extraction) that return text the policy engine does not fully understand
- False negatives (missing injection patterns) are more costly than false positives
- Your risk profile justifies the latency (5-10ms per guardrail call)

Disable (keep the default) when:
- Your tools are structured (JSON, CSV, database records) with minimal free-form text
- Your agents only use authenticated, trusted data sources
- You are cost-optimizing and can accept higher false-positive rates from deterministic scanners

To check guardrail hit rate:

```bash
curl -s http://localhost:9090/v1/metrics | grep guardrail_invocations_total
```

## Monitoring and alerting

AgentMesh emits three types of security events via OpenTelemetry: POLICY_DENY (access control), SCANNER_DETECTION (content analysis), and GUARDRAIL_INVOCATION (LLM classification).

### SecurityEvent types to alert on

**POLICY_DENY** (action: denied)

Fired when a tool call is blocked by policy. High volume can indicate compromised context or overly restrictive policy.

Alert threshold: >1 per hour in production. Single spikes are normal (user experimenting); sustained patterns suggest an attack.

```
tool: email_attachment_upload
required_trust: user
context_trust: tool
reason: context tainted by tool output
```

**SCANNER_DETECTION** (action: flagged)

Fired when deterministic scanners detect PII, injection patterns, or code. Does not block execution (unless policy also denies), but flags for monitoring.

Alert threshold: >10 per hour. Clusters of same detection type indicate specific attack vectors.

```
type: potential_injection
tool: send_message
confidence: 0.89
pattern: "execute command"
```

**GUARDRAIL_INVOCATION** (action: invoked)

Fired when the LLM guardrail is called. Purely informational. Track to understand guardrail load and cost.

Alert threshold: None. Use for budgeting. Spike may indicate new use patterns or tool changes.

```
tool: search_documents
classification: suspicious
confidence: 0.72
latency_ms: 145
```

### OTel collector configuration for SIEM routing

Edit `config/otel/collector.yaml` to route security events to your SIEM.

Current configuration exports to stdout. For production, replace the exporter:

```yaml
exporters:
  # Replace 'logging' with your SIEM exporter
  datadog:
    api:
      key: ${DD_API_KEY}
      site: datadoghq.com

  splunk:
    splunk_access_token: ${SPLUNK_HEC_TOKEN}
    endpoint: https://splunk.internal:8088

  generic_exporter:
    endpoint: https://siem.internal/otlp/v1/traces
    headers:
      Authorization: Bearer ${SIEM_TOKEN}

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch, filter/security]
      exporters: [datadog]  # or splunk, or generic_exporter
```

Restart the OTel collector:

```bash
docker compose restart otel-collector
```

### Key metrics to alert on

**Policy denies per hour**

```
tessera.policy.decisions_total{action="deny"}
```

**Scanner detection rate**

```
tessera.scanner.detections_total{type="injection|pii|code"}
```

**Guardrail invocation rate and latency**

```
tessera.guardrail.invocations_total
tessera.guardrail.latency_seconds (p50, p95, p99)
```

**Trust distribution**

```
tessera.context.min_trust_level (gauge, current value)
tessera.context.segments_by_trust (counter by trust_level)
```

Set up dashboard queries to track these metrics. Example Prometheus query:

```
rate(tessera.policy.decisions_total{action="deny"}[1h])
```

If this exceeds your alert threshold (e.g., 5 per hour in production), page oncall.

## Troubleshooting common issues

### Proxy refuses to start: "Invalid TESSERA_SIGNING_KEY"

The signing key must be a valid string. If you use an environment variable, ensure it is set:

```bash
echo $TESSERA_SIGNING_KEY
```

If empty, set it:

```bash
export TESSERA_SIGNING_KEY="my-key-32-characters-or-longer"
docker compose up tessera-proxy -d
```

### Agent cannot reach agentgateway: "Connection refused"

The agent's network namespace may not have access to the agentgateway container. Verify:

1. The agent is in the same docker compose file or network:

```bash
docker network ls | grep agentmesh
docker network inspect <network-name>
```

2. The agentgateway service is healthy:

```bash
docker compose ps agentgateway
```

3. The agent uses the correct address (container name, not localhost):

```
AGENTGATEWAY_URL: http://agentgateway:8080
```

### Tool outputs cause all subsequent tool calls to be denied

Tool outputs are marked as TOOL trust (50). If your tools return free-form text (search results, web content, documents), subsequent side-effecting tools are blocked.

Solution: If the tool is read-only, mark it `side_effects: false` in policy.yaml:

```yaml
requirements:
  - name: search_documents
    required_trust: tool
    side_effects: false
```

If the tool can modify state, either (a) re-prompt the agent with the output as a new USER-trust context, or (b) require the agent to explicitly confirm the tool output before proceeding.

### Policy changes do not take effect after restart

Verify the policy file is mounted in the tessera-proxy container:

```bash
docker compose exec tessera-proxy cat /app/policy.yaml
```

If the file is blank or old, the volume mount path is incorrect. Check `docker-compose.yml`:

```yaml
volumes:
  - ./config/tessera/policy.yaml:/app/policy.yaml:ro
```

Ensure the path is absolute or relative to the working directory. Then restart:

```bash
docker compose restart tessera-proxy
```

### OTel events not appearing in SIEM

1. Verify the OTel collector is receiving events:

```bash
docker compose logs otel-collector | grep "tessera.policy"
```

2. Check that the exporter is configured and credentials are valid:

```bash
docker compose exec otel-collector curl -v https://siem.internal/status
```

3. Verify the pipeline filter is not dropping all events:

```yaml
# In config/otel/collector.yaml, ensure the filter includes your event type
filter/security:
  error_mode: ignore
  traces:
    span:
      - 'attributes["tessera.event_kind"] != nil'
```

If no events match, the filter is too restrictive. Temporarily set it to log everything:

```yaml
exporters:
  logging:
    loglevel: debug
```

Restart and check logs.

### Out of memory: tessera-proxy container killed

The proxy caches context segments and SVID verification results. If your agents generate many concurrent connections, the cache can grow unbounded.

Solution: Set memory limits in docker-compose.yml:

```yaml
tessera-proxy:
  deploy:
    resources:
      limits:
        memory: 1G
      reservations:
        memory: 512M
```

And monitor cache statistics:

```bash
curl -s http://localhost:9090/v1/metrics | grep cache
```

If cache hits are low (< 70%), reduce the TTL for cached segments (not currently configurable, file a feature request).
