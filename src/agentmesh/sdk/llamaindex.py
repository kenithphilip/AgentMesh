"""LlamaIndex callback handler backed by the AgentMesh proxy.

Drop-in replacement for tessera.adapters.llamaindex.TesseraLlamaIndexHandler
that delegates security decisions to the AgentMesh proxy via HTTP.

Usage::

    from agentmesh.sdk.llamaindex import MeshLlamaIndexHandler
    from llama_index.core.callbacks import CallbackManager

    handler = MeshLlamaIndexHandler(proxy_url="http://localhost:9090")
    callback_manager = CallbackManager([handler])
    Settings.callback_manager = callback_manager
"""

from __future__ import annotations

from typing import Any

from agentmesh.client import MeshClient

try:
    from llama_index.core.callbacks.base_handler import BaseCallbackHandler
    from llama_index.core.callbacks.schema import CBEventType
except ImportError:
    raise ImportError(
        "llama-index-core is required for the LlamaIndex adapter. "
        "Install it with: pip install llama-index-core"
    )


class MeshLlamaIndexHandler(BaseCallbackHandler):
    """LlamaIndex callback handler that delegates to the AgentMesh proxy.

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
        super().__init__(
            event_starts_to_ignore=[],
            event_ends_to_ignore=[],
        )
        self._client = MeshClient(
            base_url=proxy_url,
            session_id=session_id,
            agent_identity=agent_identity,
        )

    def on_event_start(
        self,
        event_type: CBEventType,
        payload: dict[str, Any] | None = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        """Evaluate policy before tool execution."""
        if event_type == CBEventType.FUNCTION_CALL and payload:
            tool_name = payload.get("function_call", {}).get("name", "unknown")
            allowed, reason = self._client.evaluate(tool_name)
            if not allowed:
                raise RuntimeError(f"AgentMesh blocked {tool_name}: {reason}")
        return event_id

    def on_event_end(
        self,
        event_type: CBEventType,
        payload: dict[str, Any] | None = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Scan and label tool output."""
        if event_type == CBEventType.FUNCTION_CALL and payload:
            tool_name = payload.get("function_call", {}).get("name", "unknown")
            output = payload.get("function_call_response", "")
            self._client.label(tool_name, str(output)[:5000])

    def start_trace(self, trace_id: str | None = None) -> None:
        """No-op trace lifecycle."""

    def end_trace(
        self,
        trace_id: str | None = None,
        trace_map: dict[str, list[str]] | None = None,
    ) -> None:
        """No-op trace lifecycle."""
