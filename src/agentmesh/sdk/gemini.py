"""agentmesh.sdk.gemini

Adapter for Google Gemini CLI's tool-confirmation hooks.

Gemini CLI's hook schema has evolved. The normalizer below handles the
common fields. Confirm against your Gemini CLI version.

Stdin JSON (typical shape)::

    {
      "sessionId": "...",
      "hookType": "beforeToolUse",
      "toolName": "run_shell",
      "toolArgs": { "command": "..." }
    }

Response: Gemini CLI accepts a JSON stdout payload with ``allow`` /
``deny`` plus a reason, and uses exit codes as a fallback. We emit both.
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


class GeminiAdapter(AgentHookAdapter):
    agent_name = "gemini-cli"

    def normalize_input(self, raw: Mapping[str, Any]) -> ToolCallEnvelope:
        tool_name = str(
            raw.get("toolName") or raw.get("tool_name") or raw.get("tool") or ""
        )
        args = raw.get("toolArgs") or raw.get("tool_args") or raw.get("arguments") or {}
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
            agent_event=str(raw.get("hookType") or raw.get("event") or "beforeToolUse"),
            raw=dict(raw),
        )

    def format_response(
        self,
        env: ToolCallEnvelope,
        result: EvaluationResult,
    ) -> tuple[int, str, str]:
        if result.allowed:
            return 0, json.dumps({"decision": "allow"}), ""
        reason = result.reason or f"blocked by {result.source}"
        payload = {
            "decision": "deny",
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
    return GeminiAdapter(evaluator).run_stdio()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
