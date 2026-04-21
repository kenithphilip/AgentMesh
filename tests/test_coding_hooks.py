"""Tests for the coding-agent hook adapters (Claude Code, Cursor, Copilot, Gemini)."""

from __future__ import annotations

import io
import json
from dataclasses import dataclass
from typing import Any

import pytest

from agentmesh.sdk import (
    EvaluationResult,
    HTTPEvaluator,
    InProcessEvaluator,
    ToolCallEnvelope,
)
from agentmesh.sdk.claude_code import ClaudeCodeAdapter
from agentmesh.sdk.copilot import CopilotAdapter
from agentmesh.sdk.cursor import CursorAdapter
from agentmesh.sdk.gemini import GeminiAdapter


@dataclass
class _StubDecision:
    allowed: bool
    reason: str
    source: str = "stub"
    metadata: dict[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


def make_evaluator(decision: _StubDecision):
    def _call(*, trajectory_id, tool_name, args):
        return decision
    return InProcessEvaluator(_call)


class TestClaudeCode:
    def test_allow_is_silent(self):
        adapter = ClaudeCodeAdapter(
            make_evaluator(_StubDecision(allowed=True, reason=""))
        )
        stdin = io.StringIO(json.dumps({
            "session_id": "abc",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        }))
        stdout, stderr = io.StringIO(), io.StringIO()
        rc = adapter.run_stdio(stdin=stdin, stdout=stdout, stderr=stderr)
        assert rc == 0
        assert stdout.getvalue() == ""
        assert stderr.getvalue() == ""

    def test_block_exit_2_and_json(self):
        adapter = ClaudeCodeAdapter(
            make_evaluator(
                _StubDecision(
                    allowed=False,
                    reason="rm -rf /",
                    source="tessera.destructive_guard",
                    metadata={"pattern_id": "fs.rm_rf_root"},
                )
            )
        )
        stdin = io.StringIO(json.dumps({
            "session_id": "abc",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        }))
        stdout, stderr = io.StringIO(), io.StringIO()
        rc = adapter.run_stdio(stdin=stdin, stdout=stdout, stderr=stderr)
        assert rc == 2
        payload = json.loads(stdout.getvalue().strip())
        assert payload["decision"] == "block"
        assert "rm -rf /" in payload["reason"]
        assert payload["metadata"]["source"] == "tessera.destructive_guard"
        assert payload["metadata"]["pattern_id"] == "fs.rm_rf_root"
        assert "blocked Bash" in stderr.getvalue()

    def test_normalize_handles_missing_fields(self):
        adapter = ClaudeCodeAdapter(
            make_evaluator(_StubDecision(allowed=True, reason=""))
        )
        env = adapter.normalize_input({"tool_name": "X"})
        assert env.tool_name == "X"
        assert env.args == {}
        assert env.trajectory_id == ""

    def test_bad_json_exits_1(self):
        adapter = ClaudeCodeAdapter(
            make_evaluator(_StubDecision(allowed=True, reason=""))
        )
        stdin = io.StringIO("not json")
        stdout, stderr = io.StringIO(), io.StringIO()
        rc = adapter.run_stdio(stdin=stdin, stdout=stdout, stderr=stderr)
        assert rc == 1
        assert "bad json" in stderr.getvalue()


class TestCursor:
    def test_allow_emits_action_allow(self):
        adapter = CursorAdapter(
            make_evaluator(_StubDecision(allowed=True, reason=""))
        )
        stdin = io.StringIO(json.dumps({
            "conversationId": "c1",
            "event": "beforeToolCall",
            "tool": {"name": "run_terminal_cmd", "arguments": {"command": "ls"}},
        }))
        stdout, stderr = io.StringIO(), io.StringIO()
        rc = adapter.run_stdio(stdin=stdin, stdout=stdout, stderr=stderr)
        assert rc == 0
        assert json.loads(stdout.getvalue().strip())["action"] == "allow"

    def test_block_emits_action_block(self):
        adapter = CursorAdapter(
            make_evaluator(_StubDecision(allowed=False, reason="nope"))
        )
        stdin = io.StringIO(json.dumps({
            "conversationId": "c1",
            "tool": {"name": "run_terminal_cmd", "arguments": {"command": "x"}},
        }))
        stdout, stderr = io.StringIO(), io.StringIO()
        rc = adapter.run_stdio(stdin=stdin, stdout=stdout, stderr=stderr)
        assert rc == 2
        assert json.loads(stdout.getvalue().strip())["action"] == "block"

    def test_flat_fallback_shape(self):
        adapter = CursorAdapter(
            make_evaluator(_StubDecision(allowed=True, reason=""))
        )
        env = adapter.normalize_input({
            "sessionId": "s1",
            "toolName": "shell",
            "arguments": {"cmd": "ls"},
        })
        assert env.trajectory_id == "s1"
        assert env.tool_name == "shell"
        assert env.args == {"cmd": "ls"}


class TestCopilot:
    def test_allow_silent(self):
        adapter = CopilotAdapter(
            make_evaluator(_StubDecision(allowed=True, reason=""))
        )
        stdin = io.StringIO(json.dumps({
            "sessionId": "s1",
            "tool": "shell.exec",
            "input": {"command": "ls"},
        }))
        stdout, stderr = io.StringIO(), io.StringIO()
        rc = adapter.run_stdio(stdin=stdin, stdout=stdout, stderr=stderr)
        assert rc == 0
        assert stdout.getvalue() == ""

    def test_block_exit_1(self):
        adapter = CopilotAdapter(
            make_evaluator(_StubDecision(allowed=False, reason="blocked"))
        )
        stdin = io.StringIO(json.dumps({
            "sessionId": "s1",
            "tool": "shell.exec",
            "input": {"command": "rm -rf /"},
        }))
        stdout, stderr = io.StringIO(), io.StringIO()
        rc = adapter.run_stdio(stdin=stdin, stdout=stdout, stderr=stderr)
        assert rc == 1
        assert "shell.exec blocked" in stderr.getvalue()

    def test_tool_as_mapping(self):
        adapter = CopilotAdapter(
            make_evaluator(_StubDecision(allowed=True, reason=""))
        )
        env = adapter.normalize_input({
            "sessionId": "s1",
            "tool": {"name": "shell.exec", "input": {"command": "ls"}},
        })
        assert env.tool_name == "shell.exec"
        assert env.args == {"command": "ls"}


class TestGemini:
    def test_allow_json(self):
        adapter = GeminiAdapter(
            make_evaluator(_StubDecision(allowed=True, reason=""))
        )
        stdin = io.StringIO(json.dumps({
            "sessionId": "s1",
            "hookType": "beforeToolUse",
            "toolName": "run_shell",
            "toolArgs": {"command": "ls"},
        }))
        stdout, stderr = io.StringIO(), io.StringIO()
        rc = adapter.run_stdio(stdin=stdin, stdout=stdout, stderr=stderr)
        assert rc == 0
        assert json.loads(stdout.getvalue().strip())["decision"] == "allow"

    def test_deny_json(self):
        adapter = GeminiAdapter(
            make_evaluator(_StubDecision(allowed=False, reason="blocked"))
        )
        stdin = io.StringIO(json.dumps({
            "sessionId": "s1",
            "toolName": "run_shell",
            "toolArgs": {"command": "x"},
        }))
        stdout, stderr = io.StringIO(), io.StringIO()
        rc = adapter.run_stdio(stdin=stdin, stdout=stdout, stderr=stderr)
        assert rc == 2
        assert json.loads(stdout.getvalue().strip())["decision"] == "deny"


def test_http_evaluator_unreachable_fails_closed(monkeypatch):
    monkeypatch.delenv("TESSERA_FAIL_OPEN", raising=False)
    ev = HTTPEvaluator(endpoint="http://127.0.0.1:1")
    env = ToolCallEnvelope(
        trajectory_id="t1",
        tool_name="x",
        args={},
        agent_event="e",
    )
    result = ev.evaluate(env)
    assert not result.allowed
    assert result.metadata.get("fail_mode") == "closed"


def test_http_evaluator_unreachable_fail_open(monkeypatch):
    monkeypatch.setenv("TESSERA_FAIL_OPEN", "1")
    ev = HTTPEvaluator(endpoint="http://127.0.0.1:1")
    env = ToolCallEnvelope(
        trajectory_id="t1",
        tool_name="x",
        args={},
        agent_event="e",
    )
    result = ev.evaluate(env)
    assert result.allowed
    assert result.metadata.get("fail_mode") == "open"
