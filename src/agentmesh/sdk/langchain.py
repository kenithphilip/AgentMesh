"""LangChain callback handler backed by the AgentMesh proxy.

Drop-in replacement for tessera.adapters.langchain.TesseraCallbackHandler
that calls the proxy HTTP API instead of running scanners in-process.

Usage::

    from agentmesh.sdk.langchain import MeshCallbackHandler

    handler = MeshCallbackHandler(proxy_url="http://localhost:9090")
    chain = agent.with_config(callbacks=[handler])
    result = chain.invoke({"input": "Find hotels in Paris"})
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from agentmesh.client import MeshClient

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.tools import ToolException
except ImportError:
    raise ImportError(
        "langchain-core is required for the LangChain adapter. "
        "Install it with: pip install langchain-core"
    )


class MeshCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that delegates to the AgentMesh proxy.

    Args:
        proxy_url: AgentMesh proxy base URL.
        session_id: Session identifier for rate limiting.
        agent_identity: Optional JWT-SVID or SPIFFE ID.
    """

    raise_error: bool = True
    ignore_chat_model: bool = False
    ignore_chain: bool = True
    ignore_agent: bool = True
    ignore_retriever: bool = True
    ignore_retry: bool = True
    ignore_llm: bool = False

    def __init__(
        self,
        proxy_url: str = "http://localhost:9090",
        session_id: str = "default",
        agent_identity: str | None = None,
    ) -> None:
        super().__init__()
        self._client = MeshClient(
            base_url=proxy_url,
            session_id=session_id,
            agent_identity=agent_identity,
        )
        self._initialized = False

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """Label user prompts as trusted context."""
        if not self._initialized and prompts:
            self._client.add_prompt(prompts[0][:500])
            self._initialized = True

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """Label chat messages as trusted context."""
        if not self._initialized and messages:
            first_msg = messages[0]
            if first_msg:
                content = getattr(first_msg[-1], "content", str(first_msg[-1]))
                self._client.add_prompt(str(content)[:500])
                self._initialized = True

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """Evaluate policy before tool execution."""
        tool_name = serialized.get("name", kwargs.get("name", "unknown"))
        allowed, reason = self._client.evaluate(tool_name)
        if not allowed:
            raise ToolException(f"AgentMesh blocked {tool_name}: {reason}")

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """Scan and label tool output."""
        tool_name = kwargs.get("name", "unknown")
        self._client.label(tool_name, str(output)[:5000])

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """No-op on tool errors (let the framework handle them)."""

    def on_llm_end(self, response: Any, *, run_id: UUID, **kwargs: Any) -> None:
        """No-op. Context persists across LLM calls for agent loops."""

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """No-op (chain events ignored)."""
