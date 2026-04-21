"""PydanticAI guard backed by the AgentMesh proxy.

Drop-in replacement for tessera.adapters.pydantic_ai.TesseraPydanticAIGuard
that delegates security decisions to the AgentMesh proxy via HTTP.

Usage::

    from agentmesh.sdk.pydantic_ai import MeshPydanticAIGuard

    guard = MeshPydanticAIGuard(proxy_url="http://localhost:9090")

    @agent.tool(prepare=guard.tool_prepare)
    async def web_search(ctx, query: str) -> str:
        ...
"""

from __future__ import annotations

from typing import Any

from agentmesh.client import MeshClient

try:
    import pydantic_ai  # noqa: F401
except ImportError:
    raise ImportError(
        "pydantic-ai is required for the PydanticAI adapter. "
        "Install it with: pip install pydantic-ai"
    )


class MeshPydanticAIGuard:
    """PydanticAI tool prepare hook and result validator backed by the proxy.

    Duck-types the PydanticAI hook interface. The ``tool_prepare`` method
    blocks the tool call by raising on deny. The ``result_validator``
    labels the result so the proxy sees its content.

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

    def tool_prepare(self, ctx: Any, tool_def: Any) -> Any:
        """Evaluate the tool call. Returns the tool_def unchanged on allow.

        Raises:
            RuntimeError: If the mesh policy denies the tool call.
        """
        tool_name = getattr(tool_def, "name", str(tool_def))
        allowed, reason = self._client.evaluate(tool_name)
        if not allowed:
            raise RuntimeError(f"AgentMesh blocked {tool_name}: {reason}")
        return tool_def

    def result_validator(self, ctx: Any, result: Any) -> Any:
        """Label the result in the mesh context. Returns the result unchanged.

        The mesh proxy decides whether the result taints the context.
        Future tool calls will be blocked if the taint floor is hit.
        """
        # PydanticAI does not pass tool name to the validator, so we use
        # a generic name. The proxy still tracks the content correctly.
        self._client.label("pydantic_ai_tool", str(result)[:5000])
        return result
