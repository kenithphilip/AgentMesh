"""LangGraph guard backed by the AgentMesh proxy.

Drop-in replacement for tessera.adapters.langgraph.TesseraLangGraphGuard
that delegates security decisions to the AgentMesh proxy via HTTP.

LangGraph uses node functions rather than callbacks. The guard exposes
two node functions that update the graph state with the policy decision
without raising, so the graph can route on the result.

Usage::

    from agentmesh.sdk.langgraph import MeshLangGraphGuard
    from langgraph.graph import StateGraph

    guard = MeshLangGraphGuard(proxy_url="http://localhost:9090")
    graph = StateGraph(MyState)
    graph.add_node("check_tool", guard.check_tool_call)
    graph.add_node("label_output", guard.label_tool_output)
    graph.add_conditional_edges(
        "check_tool",
        lambda s: "denied" if s.get("mesh_blocked") else "execute_tool",
        {"denied": END, "execute_tool": "tool_node"},
    )
"""

from __future__ import annotations

from typing import Any

from agentmesh.client import MeshClient

try:
    import langgraph  # noqa: F401
except ImportError:
    raise ImportError(
        "langgraph is required for the LangGraph adapter. "
        "Install it with: pip install langgraph"
    )


class MeshLangGraphGuard:
    """LangGraph node functions backed by the AgentMesh proxy.

    Args:
        proxy_url: AgentMesh proxy base URL.
        session_id: Session identifier for rate limiting.
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

    def check_tool_call(self, state: dict[str, Any]) -> dict[str, Any]:
        """Evaluate policy before a tool call. Updates state, does not raise.

        Reads ``state['tool_name']`` and optional ``state['tool_args']``.
        Writes ``state['mesh_blocked']`` (bool) and ``state['mesh_reason']``.

        Returns:
            The updated state dict so the graph can route on the result.
        """
        tool_name = state.get("tool_name", "unknown")
        tool_args = state.get("tool_args")
        allowed, reason = self._client.evaluate(tool_name, tool_args)
        return {
            **state,
            "mesh_blocked": not allowed,
            "mesh_reason": reason if not allowed else None,
        }

    def label_tool_output(self, state: dict[str, Any]) -> dict[str, Any]:
        """Scan and label tool output. Updates state with the result.

        Reads ``state['tool_name']`` and ``state['tool_output']``.
        Writes ``state['mesh_trust_level']`` (int).

        Returns:
            The updated state dict.
        """
        tool_name = state.get("tool_name", "unknown")
        output = state.get("tool_output", "")
        result = self._client.label(tool_name, str(output)[:5000])
        return {
            **state,
            "mesh_trust_level": result.get("trust_level", 100),
            "mesh_min_trust": result.get("min_trust", 100),
        }

    def add_user_prompt(self, prompt: str) -> None:
        """Seed the proxy context with the user's prompt."""
        self._client.add_prompt(prompt)
