"""agentmesh.sdk.cursor

Adapter for Cursor's tool-invocation hooks.

Cursor's hook schema has evolved across versions; the normalizer below
maps the common fields seen in their MCP / agent-mode hooks. Confirm
against the version of Cursor you are targeting and tighten the field
names if needed.

Stdin JSON (typical shape)::

    {
      "conversationId": "...",
      "event": "beforeToolCall",
      "tool": { "name": "run_terminal_cmd",
                "arguments": { "command": "..." } },
      "workspace": "/path/to/ws"
    }

Response: Cursor accepts either a non-zero exit with stderr, or a JSON
stdout payload with ``action: "block" | "allow"``. We emit both.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Mapping

from agentmesh.sdk import (
    AgentHookAdapter,
    EvaluationResult,
    HTTPEvaluator,
    ToolCallEnvelope,
)


class CursorAdapter(AgentHookAdapter):
    agent_name = "cursor"

    def normalize_input(self, raw: Mapping[str, Any]) -> ToolCallEnvelope:
        tool = raw.get("tool")
        if isinstance(tool, Mapping):
            tool_name = str(tool.get("name") or "")
            args = tool.get("arguments")
            if not isinstance(args, dict):
                args = {}
        else:
            tool_name = str(raw.get("toolName") or raw.get("tool_name") or "")
            args = raw.get("arguments") or raw.get("args") or {}
            if not isinstance(args, dict):
                args = {}
        trajectory_id = str(
            raw.get("conversationId")
            or raw.get("conversation_id")
            or raw.get("sessionId")
            or ""
        )
        return ToolCallEnvelope(
            trajectory_id=trajectory_id,
            tool_name=tool_name,
            args=args,
            agent_event=str(raw.get("event") or "beforeToolCall"),
            raw=dict(raw),
        )

    def format_response(
        self,
        env: ToolCallEnvelope,
        result: EvaluationResult,
    ) -> tuple[int, str, str]:
        if result.allowed:
            return 0, json.dumps({"action": "allow"}), ""
        reason = result.reason or f"blocked by {result.source}"
        payload = {
            "action": "block",
            "reason": reason,
            "metadata": {"source": result.source, **result.metadata},
        }
        return (
            2,
            json.dumps(payload),
            f"[agentmesh] blocked {env.tool_name}: {reason}",
        )


def main() -> int:
    endpoint = os.environ.get("AGENTMESH_ENDPOINT")
    if not endpoint:
        print("[agentmesh] AGENTMESH_ENDPOINT not set; allowing", file=sys.stderr)
        return 0
    evaluator = HTTPEvaluator(
        endpoint=endpoint,
        api_key=os.environ.get("AGENTMESH_API_KEY"),
    )
    return CursorAdapter(evaluator).run_stdio()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
