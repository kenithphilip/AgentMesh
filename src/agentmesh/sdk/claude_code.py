"""agentmesh.sdk.claude_code

Adapter for Anthropic Claude Code's PreToolUse / PostToolUse hooks.

Hook schema (stdin JSON)::

    {
      "session_id": "abc123",
      "transcript_path": "/path/to/transcript.json",
      "cwd": "/workspace",
      "hook_event_name": "PreToolUse",
      "tool_name": "Bash",
      "tool_input": { "command": "ls -la" }
    }

Response: Claude Code accepts either an exit code + stderr, or a JSON
object on stdout describing the decision. We emit both, so older and
newer Claude Code versions both work. For a deny we exit 2 (the
Claude Code convention for "block with reason") AND print
``{"decision": "block", "reason": "..."}`` on stdout.

Install in ``.claude/settings.json``::

    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "*",
            "hooks": [
              {"type": "command",
               "command": "python -m agentmesh.sdk.claude_code"}
            ]
          }
        ]
      }
    }

Environment::

    AGENTMESH_ENDPOINT=http://localhost:9090   # required for HTTP mode
    AGENTMESH_API_KEY=...                       # optional
    TESSERA_FAIL_OPEN=0|1                       # default 0 (fail-closed)
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


class ClaudeCodeAdapter(AgentHookAdapter):
    agent_name = "claude-code"

    def normalize_input(self, raw: Mapping[str, Any]) -> ToolCallEnvelope:
        tool_input = raw.get("tool_input")
        if not isinstance(tool_input, dict):
            tool_input = {"_raw": tool_input} if tool_input is not None else {}
        return ToolCallEnvelope(
            trajectory_id=str(raw.get("session_id") or ""),
            tool_name=str(raw.get("tool_name") or ""),
            args=tool_input,
            agent_event=str(raw.get("hook_event_name") or "PreToolUse"),
            raw=dict(raw),
        )

    def format_response(
        self,
        env: ToolCallEnvelope,
        result: EvaluationResult,
    ) -> tuple[int, str, str]:
        if result.allowed:
            # Silent allow: Claude Code treats exit 0 + empty stdout as proceed.
            return 0, "", ""
        reason = result.reason or f"blocked by {result.source}"
        payload = {
            "decision": "block",
            "reason": reason,
            "metadata": {
                "source": result.source,
                **result.metadata,
            },
        }
        return (
            2,
            json.dumps(payload),
            f"[agentmesh] blocked {env.tool_name}: {reason}",
        )


def main() -> int:
    endpoint = os.environ.get("AGENTMESH_ENDPOINT")
    if not endpoint:
        print(
            "[agentmesh] AGENTMESH_ENDPOINT not set; allowing "
            "(configure to enforce)",
            file=sys.stderr,
        )
        return 0
    evaluator = HTTPEvaluator(
        endpoint=endpoint,
        api_key=os.environ.get("AGENTMESH_API_KEY"),
    )
    return ClaudeCodeAdapter(evaluator).run_stdio()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
