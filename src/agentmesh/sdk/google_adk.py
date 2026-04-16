"""Google ADK callbacks backed by the AgentMesh proxy.

Usage::

    from agentmesh.sdk.google_adk import MeshADKCallbacks

    callbacks = MeshADKCallbacks(proxy_url="http://localhost:9090")
    # Pass callbacks.before_tool and callbacks.after_tool to ADK agent
"""

from __future__ import annotations

from typing import Any

from agentmesh.client import MeshClient


class MeshADKCallbacks:
    """Google ADK-compatible callbacks that delegate to the AgentMesh proxy.

    ADK uses function callbacks rather than a class interface. Pass
    ``before_tool_callback`` and ``after_tool_callback`` directly.

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

    def before_tool_callback(self, callback_context: Any) -> dict[str, Any] | None:
        """Evaluate policy before tool execution.

        Returns None to allow, or a dict with blocked=True to deny.
        ADK expects this return signature.
        """
        tool_name = getattr(callback_context, "tool_name", "unknown")
        allowed, reason = self._client.evaluate(tool_name)
        if not allowed:
            return {"blocked": True, "reason": reason}
        return None

    def after_tool_callback(self, callback_context: Any) -> None:
        """Scan and label tool output."""
        tool_name = getattr(callback_context, "tool_name", "unknown")
        output = getattr(callback_context, "output", "")
        self._client.label(tool_name, str(output)[:5000])
