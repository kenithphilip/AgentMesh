"""NeMo Guardrails action backed by the AgentMesh proxy.

Drop-in replacement for tessera.adapters.nemo.TesseraRailAction that
delegates security decisions to the AgentMesh proxy via HTTP.

Exposes a NeMo @action that Colang flows can call to evaluate tool
calls against the mesh policy.

Usage::

    from agentmesh.sdk.nemo import MeshRailAction

    action = MeshRailAction(proxy_url="http://localhost:9090")
    rails.register_action(action.check_tool_call, name="mesh_check")

In Colang::

    define flow check tool call
        $result = execute mesh_check(tool=$tool, content=$content)
        if $result.blocked
            bot refuse to execute tool
"""

from __future__ import annotations

from typing import Any

from agentmesh.client import MeshClient


class MeshRailAction:
    """NeMo Guardrails action backed by the AgentMesh proxy.

    NeMo Guardrails is optional: this adapter does not require nemo
    at import time, only at registration time. The action methods
    return plain dicts that NeMo can consume.

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

    async def check_tool_call(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        content: str | None = None,
    ) -> dict[str, Any]:
        """NeMo @action that evaluates a tool call against the mesh policy.

        Args:
            tool: Name of the tool to evaluate.
            args: Tool call arguments.
            content: Optional content to label first (e.g., RAG retrieval).

        Returns:
            Dict with ``allowed`` (bool), ``blocked`` (bool), and
            ``reason`` (str). NeMo Colang flows can route on these.
        """
        if content:
            self._client.label(tool, content[:5000])
        allowed, reason = self._client.evaluate(tool, args)
        return {
            "allowed": allowed,
            "blocked": not allowed,
            "reason": reason,
        }

    async def label_content(
        self,
        source: str,
        content: str,
    ) -> dict[str, Any]:
        """NeMo @action to label retrieved content in the mesh context."""
        result = self._client.label(source, content[:5000])
        return {
            "trust_level": result.get("trust_level", 100),
            "min_trust": result.get("min_trust", 100),
        }
