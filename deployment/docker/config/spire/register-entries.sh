#!/bin/sh
# Register SPIRE workload entries for AgentMesh components.
# Runs once after SPIRE server is healthy.

set -e

echo "Waiting for SPIRE server..."
sleep 5

# Register the Tessera proxy
/opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://agentmesh.local/tessera-proxy \
  -parentID spiffe://agentmesh.local/spire-agent \
  -selector docker:label:com.agentmesh.role:tessera-proxy \
  -ttl 3600 \
  -socketPath /tmp/spire/registration.sock \
  2>/dev/null || echo "Tessera proxy entry may already exist"

# Register the demo agent
/opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://agentmesh.local/demo-agent \
  -parentID spiffe://agentmesh.local/spire-agent \
  -selector docker:label:com.agentmesh.role:demo-agent \
  -ttl 3600 \
  -socketPath /tmp/spire/registration.sock \
  2>/dev/null || echo "Demo agent entry may already exist"

# Register the demo tool server
/opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://agentmesh.local/demo-tools \
  -parentID spiffe://agentmesh.local/spire-agent \
  -selector docker:label:com.agentmesh.role:demo-tools \
  -ttl 3600 \
  -socketPath /tmp/spire/registration.sock \
  2>/dev/null || echo "Demo tools entry may already exist"

echo "SPIRE workload entries registered."
