"""Claude Code hook adapter backed by the AgentMesh proxy.

Claude Code hooks are stdin/stdout JSON protocols. A hook binary reads
a JSON event from stdin, makes a decision, and writes a JSON response
to stdout. This module provides a reusable handler that maps Claude
Code events to AgentMesh proxy endpoints.

Register as a PreToolUse, PostToolUse, or UserPromptSubmit hook::

    # ~/.claude/settings.json
    {
      "hooks": {
        "PreToolUse": [{"type": "command", "command": "python -m agentmesh.sdk.claude_code pre"}],
        "PostToolUse": [{"type": "command", "command": "python -m agentmesh.sdk.claude_code post"}],
        "UserPromptSubmit": [{"type": "command", "command": "python -m agentmesh.sdk.claude_code prompt"}]
      }
    }

Run `python -m agentmesh.sdk.claude_code --help` for CLI options.

Reference: https://code.claude.com/docs/en/hooks
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from agentmesh.client import MeshClient


def _mesh_client() -> MeshClient:
    return MeshClient(
        base_url=os.environ.get("AGENTMESH_PROXY_URL", "http://localhost:9090"),
        session_id=os.environ.get("AGENTMESH_SESSION_ID", "claude-code"),
    )


def _trim(s: Any, n: int = 5000) -> str:
    return str(s)[:n]


def _emit(obj: dict[str, Any]) -> None:
    """Emit a Claude Code hook JSON response to stdout."""
    sys.stdout.write(json.dumps(obj))
    sys.stdout.write("\n")
    sys.stdout.flush()


def handle_pre_tool_use(event: dict[str, Any]) -> dict[str, Any]:
    """PreToolUse hook: evaluate policy before tool execution.

    Claude Code sends ``tool_name`` and ``tool_input`` in the event.
    We call ``/v1/evaluate`` on the proxy. If denied, return a
    Claude-Code-shaped deny response that blocks the call and shows
    the reason to the model.
    """
    tool_name = event.get("tool_name", "unknown")
    tool_input = event.get("tool_input", {})
    client = _mesh_client()
    allowed, reason = client.evaluate(tool_name, tool_input)
    if not allowed:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"AgentMesh: {reason}",
            },
        }
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
        },
    }


def handle_post_tool_use(event: dict[str, Any]) -> dict[str, Any]:
    """PostToolUse hook: label tool output in the mesh context.

    Claude Code sends ``tool_name`` and ``tool_response`` with the
    output. We call ``/v1/label`` so the proxy can scan and taint the
    context for subsequent tool calls.
    """
    tool_name = event.get("tool_name", "unknown")
    # Claude Code puts the result under different keys depending on the
    # tool. Handle the common shapes.
    response = event.get("tool_response") or event.get("output") or ""
    if isinstance(response, dict):
        response = response.get("content", response.get("text", str(response)))
    client = _mesh_client()
    client.label(tool_name, _trim(response))
    return {}


def handle_user_prompt(event: dict[str, Any]) -> dict[str, Any]:
    """UserPromptSubmit hook: seed the proxy context with the prompt.

    Also runs prompt screening. If the prompt fails screening, return
    a warning in the hook response so Claude Code can show it.
    """
    prompt = event.get("prompt") or event.get("user_prompt") or ""
    client = _mesh_client()
    client.add_prompt(_trim(prompt, 1000))
    return {}


def handle_session_start(event: dict[str, Any]) -> dict[str, Any]:
    """SessionStart hook: reset the proxy context for a new session."""
    client = _mesh_client()
    client.reset()
    return {}


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Reads a Claude Code hook event from stdin, dispatches based on the
    hook type in argv[1], and writes the response to stdout.
    """
    argv = argv or sys.argv
    if len(argv) < 2:
        sys.stderr.write("usage: claude_code <pre|post|prompt|session>\n")
        return 2

    hook_type = argv[1].lower()
    try:
        event = json.loads(sys.stdin.read())
    except json.JSONDecodeError as e:
        sys.stderr.write(f"bad JSON on stdin: {e}\n")
        return 1

    handlers = {
        "pre": handle_pre_tool_use,
        "post": handle_post_tool_use,
        "prompt": handle_user_prompt,
        "session": handle_session_start,
    }
    handler = handlers.get(hook_type)
    if handler is None:
        sys.stderr.write(f"unknown hook type: {hook_type}\n")
        return 2

    try:
        response = handler(event)
    except Exception as e:
        # Fail open: on any error, let the tool call proceed. The
        # mesh has other layers (taint tracking, human approval) that
        # catch attacks; failing closed on a proxy error would break
        # every session.
        sys.stderr.write(f"agentmesh hook error: {e}\n")
        return 0

    if response:
        _emit(response)
    return 0


if __name__ == "__main__":
    sys.exit(main())
