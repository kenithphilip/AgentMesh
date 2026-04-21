"""Haystack pipeline component backed by the AgentMesh proxy.

Drop-in replacement for tessera.adapters.haystack.TesseraHaystackGuard
that delegates security decisions to the AgentMesh proxy via HTTP.

Usage::

    from agentmesh.sdk.haystack import MeshHaystackGuard

    guard = MeshHaystackGuard(proxy_url="http://localhost:9090")
    pipeline.add_component("mesh_guard", guard)
"""

from __future__ import annotations

from typing import Any

from agentmesh.client import MeshClient

try:
    import haystack  # noqa: F401
except ImportError:
    raise ImportError(
        "haystack-ai is required for the Haystack adapter. "
        "Install it with: pip install haystack-ai"
    )


class MeshHaystackGuard:
    """Haystack pipeline component that delegates to the AgentMesh proxy.

    Duck-types the Haystack >=2.0 component interface. Insert this
    component into a pipeline before tool execution.

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

    def run(
        self,
        tool_name: str,
        tool_input: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Evaluate the tool call against the mesh policy.

        Returns:
            ``{"allowed": True}`` if permitted, else
            ``{"blocked": True, "reason": str}``.
        """
        allowed, reason = self._client.evaluate(tool_name, tool_input)
        if not allowed:
            return {"blocked": True, "reason": reason}
        return {"allowed": True}

    def label_output(self, tool_name: str, output: Any) -> None:
        """Label tool output in the mesh context.

        Call after tool execution to update the session context.
        """
        self._client.label(tool_name, str(output)[:5000])
