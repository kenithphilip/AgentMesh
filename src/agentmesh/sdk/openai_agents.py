"""OpenAI Agents SDK hooks backed by the AgentMesh proxy.

Drop-in replacement for tessera.adapters.openai_agents.TesseraAgentHooks
that calls the proxy HTTP API instead of running scanners in-process.

Usage::

    from agentmesh.sdk.openai_agents import MeshAgentHooks
    from agents import Agent, Runner

    hooks = MeshAgentHooks(proxy_url="http://localhost:9090")
    agent = Agent(name="travel", hooks=hooks, ...)
    result = Runner.run_sync(agent, "Find hotels in Paris")
"""

from __future__ import annotations

from typing import Any

from agentmesh.client import MeshClient

try:
    from agents import AgentHooks
except ImportError:
    raise ImportError(
        "openai-agents is required for the OpenAI Agents adapter. "
        "Install it with: pip install openai-agents"
    )


class MeshAgentHooks(AgentHooks):
    """OpenAI Agents hook that delegates to the AgentMesh proxy.

    Args:
        proxy_url: AgentMesh proxy base URL.
        session_id: Session identifier.
        agent_identity: Optional JWT-SVID or SPIFFE ID.
    """

    def __init__(
        self,
        proxy_url: str = "http://localhost:9090",
        session_id: str = "default",
        agent_identity: str | None = None,
    ) -> None:
        self._client = MeshClient(
            base_url=proxy_url,
            session_id=session_id,
            agent_identity=agent_identity,
        )

    async def on_agent_start(
        self, context: Any, agent: Any,
    ) -> None:
        """Reset context for a new agent run."""
        self._client.reset()

    async def on_tool_start(
        self, context: Any, agent: Any, tool: Any,
    ) -> None:
        """Evaluate policy before tool execution."""
        tool_name = getattr(tool, "name", str(tool))
        allowed, reason = self._client.evaluate(tool_name)
        if not allowed:
            raise RuntimeError(f"AgentMesh blocked {tool_name}: {reason}")

    async def on_tool_end(
        self, context: Any, agent: Any, tool: Any, result: str,
    ) -> None:
        """Scan and label tool output."""
        tool_name = getattr(tool, "name", str(tool))
        self._client.label(tool_name, str(result)[:5000])
