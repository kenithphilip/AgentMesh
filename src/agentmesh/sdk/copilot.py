"""agentmesh.sdk.copilot

Adapter for GitHub Copilot CLI's tool-evaluation hooks.

Copilot CLI's hook schema varies across versions. The normalizer below
handles the common fields. Confirm against your Copilot CLI version and
tighten if needed.

Stdin JSON (typical shape)::

    {
      "sessionId": "...",
      "event": "preToolCall",
      "tool": "shell.exec",
      "input": { "command": "..." }
    }

Response: exit 0 = allow, exit 1 = block (with message on stderr).
Copilot CLI does not consistently parse stdout JSON across versions so
we keep the response minimal: exit code + single-line stderr reason.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Mapping

from agentmesh.sdk import (
    AgentHookAdapter,
    EvaluationResult,
    HTTPEvaluator,
    ToolCallEnvelope,
)


class CopilotAdapter(AgentHookAdapter):
    agent_name = "copilot-cli"

    def normalize_input(self, raw: Mapping[str, Any]) -> ToolCallEnvelope:
        tool = raw.get("tool")
        if isinstance(tool, Mapping):
            tool_name = str(tool.get("name") or "")
            args = tool.get("input") or tool.get("arguments") or {}
        else:
            tool_name = str(tool or raw.get("tool_name") or "")
            args = raw.get("input") or raw.get("arguments") or raw.get("args") or {}
        if not isinstance(args, dict):
            args = {}
        trajectory_id = str(
            raw.get("sessionId")
            or raw.get("session_id")
            or raw.get("conversationId")
            or ""
        )
        return ToolCallEnvelope(
            trajectory_id=trajectory_id,
            tool_name=tool_name,
            args=args,
            agent_event=str(raw.get("event") or "preToolCall"),
            raw=dict(raw),
        )

    def format_response(
        self,
        env: ToolCallEnvelope,
        result: EvaluationResult,
    ) -> tuple[int, str, str]:
        if result.allowed:
            return 0, "", ""
        reason = result.reason or f"blocked by {result.source}"
        return 1, "", f"[agentmesh] {env.tool_name} blocked: {reason}"


def main() -> int:
    endpoint = os.environ.get("AGENTMESH_ENDPOINT")
    if not endpoint:
        print("[agentmesh] AGENTMESH_ENDPOINT not set; allowing", file=sys.stderr)
        return 0
    evaluator = HTTPEvaluator(
        endpoint=endpoint,
        api_key=os.environ.get("AGENTMESH_API_KEY"),
    )
    return CopilotAdapter(evaluator).run_stdio()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
