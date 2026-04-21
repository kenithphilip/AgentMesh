"""Generic coding-agent hook adapter backed by the AgentMesh proxy.

Cursor, GitHub Copilot, and Gemini CLI all use stdin/stdout JSON hook
protocols with slightly different event shapes. This module provides
a configurable handler that normalizes common field names and maps
events to AgentMesh proxy endpoints.

For Claude Code specifically, prefer ``agentmesh.sdk.claude_code``
which handles its specific field shapes.

Usage as a hook binary::

    # Cursor hook
    python -m agentmesh.sdk.coding_agent --agent cursor --hook pre-tool

    # Gemini CLI hook
    python -m agentmesh.sdk.coding_agent --agent gemini --hook pre-tool

    # Copilot hook
    python -m agentmesh.sdk.coding_agent --agent copilot --hook pre-tool

Configure the proxy URL via AGENTMESH_PROXY_URL (default
http://localhost:9090).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from agentmesh.client import MeshClient


# Field-name aliases for each agent. Each agent uses slightly different
# JSON field names for the same concept. This table normalizes them.
_AGENT_FIELDS: dict[str, dict[str, tuple[str, ...]]] = {
    "cursor": {
        "tool_name": ("tool", "tool_name", "name"),
        "tool_args": ("args", "arguments", "input", "tool_input"),
        "tool_output": ("output", "result", "response"),
        "prompt": ("prompt", "user_prompt", "query"),
    },
    "copilot": {
        "tool_name": ("tool_name", "name"),
        "tool_args": ("tool_input", "input", "arguments"),
        "tool_output": ("tool_output", "output", "response"),
        "prompt": ("prompt", "request"),
    },
    "gemini": {
        "tool_name": ("tool", "tool_name", "function"),
        "tool_args": ("args", "arguments", "parameters"),
        "tool_output": ("output", "result"),
        "prompt": ("prompt", "query"),
    },
    "generic": {
        "tool_name": ("tool_name", "tool", "name", "function"),
        "tool_args": ("tool_input", "input", "args", "arguments", "parameters"),
        "tool_output": ("tool_output", "output", "result", "response"),
        "prompt": ("prompt", "user_prompt", "query", "request"),
    },
}


def _pick(event: dict[str, Any], aliases: tuple[str, ...]) -> Any:
    for name in aliases:
        if name in event:
            return event[name]
    return None


def _trim(s: Any, n: int = 5000) -> str:
    return str(s)[:n]


def _mesh_client(session_id: str = "coding-agent") -> MeshClient:
    return MeshClient(
        base_url=os.environ.get("AGENTMESH_PROXY_URL", "http://localhost:9090"),
        session_id=os.environ.get("AGENTMESH_SESSION_ID", session_id),
    )


def handle_pre_tool(event: dict[str, Any], agent: str) -> dict[str, Any]:
    """Evaluate a pending tool call. Return ``{"allow": False, "reason": ...}``
    on deny, empty dict on allow. The hook consumer maps this to the
    agent-specific response format.
    """
    fields = _AGENT_FIELDS.get(agent, _AGENT_FIELDS["generic"])
    tool_name = _pick(event, fields["tool_name"]) or "unknown"
    tool_args = _pick(event, fields["tool_args"]) or {}
    if not isinstance(tool_args, dict):
        tool_args = {"_raw": tool_args}

    client = _mesh_client(f"{agent}-session")
    allowed, reason = client.evaluate(str(tool_name), tool_args)
    if not allowed:
        return {
            "allow": False,
            "reason": f"AgentMesh: {reason}",
            "tool": tool_name,
        }
    return {"allow": True}


def handle_post_tool(event: dict[str, Any], agent: str) -> dict[str, Any]:
    """Label tool output in the mesh context."""
    fields = _AGENT_FIELDS.get(agent, _AGENT_FIELDS["generic"])
    tool_name = _pick(event, fields["tool_name"]) or "unknown"
    output = _pick(event, fields["tool_output"]) or ""
    if isinstance(output, dict):
        output = output.get("content", output.get("text", str(output)))

    client = _mesh_client(f"{agent}-session")
    result = client.label(str(tool_name), _trim(output))
    return {
        "trust_level": result.get("trust_level"),
        "min_trust": result.get("min_trust"),
    }


def handle_user_prompt(event: dict[str, Any], agent: str) -> dict[str, Any]:
    """Seed the mesh context with the user's prompt."""
    fields = _AGENT_FIELDS.get(agent, _AGENT_FIELDS["generic"])
    prompt = _pick(event, fields["prompt"]) or ""
    client = _mesh_client(f"{agent}-session")
    client.add_prompt(_trim(prompt, 1000))
    return {}


def handle_session_start(event: dict[str, Any], agent: str) -> dict[str, Any]:
    client = _mesh_client(f"{agent}-session")
    client.reset()
    return {}


_HANDLERS = {
    "pre-tool": handle_pre_tool,
    "post-tool": handle_post_tool,
    "user-prompt": handle_user_prompt,
    "session-start": handle_session_start,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="AgentMesh hook adapter for coding agents",
    )
    parser.add_argument(
        "--agent",
        choices=list(_AGENT_FIELDS.keys()),
        default="generic",
        help="Which coding agent is calling the hook (affects JSON field parsing)",
    )
    parser.add_argument(
        "--hook",
        choices=list(_HANDLERS.keys()),
        required=True,
        help="Hook lifecycle event type",
    )
    args = parser.parse_args(argv)

    try:
        event = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError as e:
        sys.stderr.write(f"bad JSON on stdin: {e}\n")
        return 1

    try:
        response = _HANDLERS[args.hook](event, args.agent)
    except Exception as e:
        # Fail open on any hook error (see claude_code.py for rationale)
        sys.stderr.write(f"agentmesh hook error: {e}\n")
        return 0

    if response:
        sys.stdout.write(json.dumps(response))
        sys.stdout.write("\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
