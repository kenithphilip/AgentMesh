"""CrewAI callback backed by the AgentMesh proxy.

Usage::

    from agentmesh.sdk.crewai import MeshCrewCallback

    callback = MeshCrewCallback(proxy_url="http://localhost:9090")
    # Register with CrewAI's callback system
"""

from __future__ import annotations

from typing import Any

from agentmesh.client import MeshClient


class MeshCrewCallback:
    """CrewAI-compatible callback that delegates to the AgentMesh proxy.

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

    def on_tool_start(self, tool_name: str, tool_input: dict) -> None:
        """Evaluate policy before tool execution."""
        allowed, reason = self._client.evaluate(tool_name, tool_input)
        if not allowed:
            raise RuntimeError(f"AgentMesh blocked {tool_name}: {reason}")

    def on_tool_end(self, tool_name: str, output: Any) -> None:
        """Scan and label tool output."""
        self._client.label(tool_name, str(output)[:5000])
