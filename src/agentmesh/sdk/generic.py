"""Framework-agnostic mesh guard backed by the proxy HTTP API.

Use this when your framework does not have a dedicated adapter, or
when you want manual control over the evaluation pipeline.

Usage::

    from agentmesh.sdk.generic import MeshGuard

    guard = MeshGuard(proxy_url="http://localhost:9090")
    guard.start_session("Find hotels and email me the best one")

    # Before each tool call
    ok, reason = guard.before_tool("search_hotels")

    # After each tool call
    guard.after_tool("search_hotels", tool_output)

    # Before sending the model response to the user
    safe = guard.before_response(model_response, "find hotels")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentmesh.client import MeshClient


@dataclass
class MeshGuard:
    """Framework-agnostic security guard backed by the proxy.

    Args:
        proxy_url: AgentMesh proxy base URL.
        session_id: Session identifier.
        agent_identity: Optional JWT-SVID or SPIFFE ID.
        injection_threshold: Minimum score to consider tainted (informational).
    """

    proxy_url: str = "http://localhost:9090"
    session_id: str = "default"
    agent_identity: str | None = None
    injection_threshold: float = 0.75

    _client: MeshClient = field(default=None, init=False, repr=False)
    _started: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self._client = MeshClient(
            base_url=self.proxy_url,
            session_id=self.session_id,
            agent_identity=self.agent_identity,
        )

    def start_session(self, user_prompt: str) -> dict[str, Any]:
        """Initialize the session with a user prompt.

        The proxy screens the prompt and adds it to the context.
        """
        self._client.reset()
        result = self._client.add_prompt(user_prompt)
        self._started = True
        return result

    def before_tool(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        """Check if a tool call is allowed. Call before executing the tool.

        Returns (allowed, reason).
        """
        return self._client.evaluate(tool_name, args)

    def after_tool(self, tool_name: str, output: str) -> dict[str, Any]:
        """Label and scan tool output. Call after the tool executes.

        Returns label result with trust level and context state.
        """
        return self._client.label(tool_name, output)

    def before_response(
        self,
        model_response: str,
        user_task: str = "",
    ) -> bool:
        """Check model response for output manipulation before sending to user.

        Returns True if safe, False if potentially manipulated.
        """
        result = self._client.check_output(model_response, user_task)
        return result.get("safe", True)

    def scan_rag_chunk(
        self,
        text: str,
        source_id: str = "unknown",
        user_prompt: str | None = None,
    ) -> dict[str, Any]:
        """Scan a RAG retrieval chunk before adding it to context."""
        return self._client.scan_rag(text, source_id, user_prompt)

    @property
    def context_state(self) -> dict[str, Any]:
        """Current context state from the proxy."""
        return self._client.context()

    def close(self) -> None:
        """Clean up resources."""
        self._client.close()

    def __enter__(self) -> MeshGuard:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
