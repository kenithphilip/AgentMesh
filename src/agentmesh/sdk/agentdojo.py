"""AgentDojo pipeline elements backed by the AgentMesh proxy.

Drop-in replacement for tessera.adapters.agentdojo that delegates
security decisions to the AgentMesh proxy via HTTP.

AgentDojo expects two pipeline elements:

- MeshToolLabeler: sits AFTER ToolsExecutor in the loop. Labels each
  tool result with the mesh proxy.
- MeshToolGuard: sits BEFORE the LLM in the loop. Intercepts pending
  tool calls and replaces denied calls with an error message.

Usage::

    from agentmesh.sdk.agentdojo import MeshToolLabeler, MeshToolGuard
    from agentdojo.agent_pipeline import (
        AgentPipeline, InitQuery, SystemMessage, ToolsExecutor,
        ToolsExecutionLoop,
    )

    labeler = MeshToolLabeler(proxy_url="http://localhost:9090")
    guard = MeshToolGuard(client=labeler._client)

    pipeline = AgentPipeline([
        SystemMessage(...), InitQuery(), llm,
        ToolsExecutionLoop([
            ToolsExecutor(),
            labeler,    # label outputs
            guard,      # block tainted tool calls
            llm,
        ]),
    ])
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from agentmesh.client import MeshClient

try:
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    _AGENTDOJO_AVAILABLE = True
except ImportError:
    _AGENTDOJO_AVAILABLE = False

    class BasePipelineElement:  # type: ignore[no-redef]
        name: str | None = None

        def query(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError


@dataclass
class MeshToolLabeler(BasePipelineElement):
    """Label tool result messages via the AgentMesh proxy.

    Walks new tool messages and calls ``client.label`` on each so the
    proxy can scan the content and update its taint state.

    Args:
        proxy_url: AgentMesh proxy base URL.
        session_id: Session identifier for rate limiting.
    """

    name: str | None = "mesh_labeler"
    proxy_url: str = "http://localhost:9090"
    session_id: str = "default"
    _client: Any = field(default=None, init=False, repr=False)
    _labeled_count: int = field(default=0, init=False, repr=False)
    _seeded_prompt: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self._client = MeshClient(
            base_url=self.proxy_url, session_id=self.session_id,
        )

    def query(
        self,
        query: str,
        runtime: Any,
        env: Any = None,
        messages: Sequence[Any] = (),
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, Any, Any, Sequence[Any], dict[str, Any]]:
        if extra_args is None:
            extra_args = {}

        # Seed the user prompt on first call
        if not self._seeded_prompt:
            self._client.add_prompt(query[:1000])
            self._seeded_prompt = True

        # Label new tool messages
        tool_msgs = [m for m in messages if m.get("role") == "tool"]
        for msg in tool_msgs[self._labeled_count:]:
            content = msg.get("content")
            text = self._extract_text(content)
            if not text.strip():
                self._labeled_count += 1
                continue
            tool_name = self._find_tool_name(msg, messages)
            self._client.label(tool_name or "unknown", text[:5000])
            self._labeled_count += 1

        return query, runtime, env, messages, extra_args

    @staticmethod
    def _extract_text(content: Any) -> str:
        if content is None:
            return ""
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict) and block.get("content"):
                    parts.append(str(block["content"]))
            return "\n".join(parts)
        return str(content)

    @staticmethod
    def _find_tool_name(msg: Any, messages: Sequence[Any]) -> str:
        tool_call_id = msg.get("tool_call_id", "")
        for prev in reversed(list(messages)):
            if prev.get("role") == "assistant" and prev.get("tool_calls"):
                for tc in prev["tool_calls"]:
                    tc_id = tc.id if hasattr(tc, "id") else tc.get("id", "")
                    if tc_id == tool_call_id:
                        return (
                            tc.function if hasattr(tc, "function")
                            else tc.get("function", "")
                        )
        return ""


@dataclass
class MeshToolGuard(BasePipelineElement):
    """Block tool calls denied by the AgentMesh proxy.

    Sits before the LLM in the tools loop. After the LLM returns a
    response with tool_calls, this element evaluates each call against
    the proxy. Denied calls are replaced with an error tool message
    so the LLM can react instead of executing the call.

    Args:
        client: An existing MeshClient (typically shared with the labeler).
        proxy_url: Used only when client is None.
        session_id: Used only when client is None.
    """

    name: str | None = "mesh_guard"
    client: Any = None
    proxy_url: str = "http://localhost:9090"
    session_id: str = "default"

    def __post_init__(self) -> None:
        if self.client is None:
            self.client = MeshClient(
                base_url=self.proxy_url, session_id=self.session_id,
            )

    def query(
        self,
        query: str,
        runtime: Any,
        env: Any = None,
        messages: Sequence[Any] = (),
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, Any, Any, Sequence[Any], dict[str, Any]]:
        if extra_args is None:
            extra_args = {}

        # Find the most recent assistant message with tool_calls
        last_assistant = None
        for m in reversed(list(messages)):
            if m.get("role") == "assistant" and m.get("tool_calls"):
                last_assistant = m
                break
        if last_assistant is None:
            return query, runtime, env, messages, extra_args

        # Evaluate each pending tool call
        new_messages = list(messages)
        for tc in last_assistant.get("tool_calls", []):
            tool_name = (
                tc.function if hasattr(tc, "function") else tc.get("function", "")
            )
            tc_id = tc.id if hasattr(tc, "id") else tc.get("id", "")
            allowed, reason = self.client.evaluate(tool_name)
            if not allowed:
                # Replace with an error tool message so the LLM sees
                # the denial without executing the tool
                new_messages.append({
                    "role": "tool",
                    "tool_call_id": tc_id,
                    "content": f"BLOCKED by AgentMesh: {reason}",
                })

        return query, runtime, env, tuple(new_messages), extra_args
