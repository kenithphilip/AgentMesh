"""agentmesh.sdk

Adapters for external coding-agent hook protocols (Claude Code, Cursor,
Copilot CLI, Gemini CLI) plus the existing framework-callback adapters
(LangChain, CrewAI, LlamaIndex, etc.).

Coding-agent hooks share a stdin-JSON / stdout-JSON + exit-code shape.
The :class:`AgentHookAdapter` base class normalizes that shape::

    stdin JSON
      |
      v
    normalize_input()   -> ToolCallEnvelope
      |
      v
    evaluator.evaluate()  -> EvaluationResult
      |
      v
    format_response()   -> (exit_code, stdout, stderr)
      |
      v
    stdout + stderr + exit

Adapters are short-lived processes invoked per hook. HTTPEvaluator uses
stdlib urllib so adapters have no third-party deps at runtime.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import IO, Any, Callable, Mapping, Protocol

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ToolCallEnvelope:
    """Normalized view of a coding-agent tool-call hook event."""

    trajectory_id: str
    tool_name: str
    args: dict[str, Any]
    agent_event: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvaluationResult:
    """Adapter-facing decision, derived from a proxy or in-process evaluator."""

    allowed: bool
    reason: str = ""
    source: str = "agentmesh"
    metadata: dict[str, Any] = field(default_factory=dict)


class Evaluator(Protocol):
    """Transport-neutral interface every adapter consumes."""

    def evaluate(self, env: ToolCallEnvelope) -> EvaluationResult: ...


def _fail_open() -> bool:
    return os.environ.get("TESSERA_FAIL_OPEN", "").strip() in {"1", "true", "yes"}


class HTTPEvaluator:
    """POSTs the envelope to the mesh proxy. Dependency-free (urllib)."""

    def __init__(
        self,
        endpoint: str,
        api_key: str | None = None,
        path: str = "/v1/evaluate",
        timeout: float = 5.0,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._path = path
        self._timeout = timeout

    def evaluate(self, env: ToolCallEnvelope) -> EvaluationResult:
        url = f"{self._endpoint}{self._path}"
        payload = json.dumps({
            "tool_name": env.tool_name,
            "args": env.args,
            "session_id": env.trajectory_id or "default",
        }).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        if self._api_key:
            req.add_header("Authorization", f"Bearer {self._api_key}")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = resp.read().decode("utf-8")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            mode = "open" if _fail_open() else "closed"
            return EvaluationResult(
                allowed=_fail_open(),
                reason=f"evaluator unreachable ({e})",
                source="agentmesh.sdk",
                metadata={"fail_mode": mode},
            )

        try:
            data = json.loads(body)
        except Exception as e:
            mode = "open" if _fail_open() else "closed"
            return EvaluationResult(
                allowed=_fail_open(),
                reason=f"evaluator bad response ({e})",
                source="agentmesh.sdk",
                metadata={"fail_mode": mode},
            )

        allowed = bool(data.get("allowed", False))
        return EvaluationResult(
            allowed=allowed,
            reason=str(data.get("reason", "")),
            source=str(data.get("source", "agentmesh")),
            metadata={
                k: v for k, v in data.items()
                if k not in {"allowed", "reason", "source"}
            },
        )


class InProcessEvaluator:
    """Wraps any callable with the ``(trajectory_id, tool_name, args)``
    signature as an :class:`Evaluator`.

    Expects the callable to return an object with ``allowed``, ``reason``,
    ``source``, and ``metadata`` attributes (dataclass or duck-typed).
    """

    def __init__(
        self,
        call: Callable[..., Any],
    ) -> None:
        self._call = call

    def evaluate(self, env: ToolCallEnvelope) -> EvaluationResult:
        result = self._call(
            trajectory_id=env.trajectory_id,
            tool_name=env.tool_name,
            args=env.args,
        )
        return EvaluationResult(
            allowed=bool(getattr(result, "allowed", False)),
            reason=str(getattr(result, "reason", "")),
            source=str(getattr(result, "source", "agentmesh")),
            metadata=dict(getattr(result, "metadata", {}) or {}),
        )


class AgentHookAdapter(ABC):
    """Base class for stdin/stdout JSON coding-agent hooks.

    Subclass and implement ``normalize_input`` (agent-specific JSON ->
    :class:`ToolCallEnvelope`) and ``format_response`` (envelope + result
    -> (exit_code, stdout, stderr)).

    The :meth:`run_stdio` method is the entrypoint called from the
    per-agent ``main()`` wrappers. It accepts IO streams for testability.
    """

    agent_name: str = "generic"

    def __init__(self, evaluator: Evaluator) -> None:
        self._evaluator = evaluator

    @abstractmethod
    def normalize_input(self, raw: Mapping[str, Any]) -> ToolCallEnvelope: ...

    @abstractmethod
    def format_response(
        self,
        env: ToolCallEnvelope,
        result: EvaluationResult,
    ) -> tuple[int, str, str]: ...

    def run_stdio(
        self,
        stdin: IO[str] | None = None,
        stdout: IO[str] | None = None,
        stderr: IO[str] | None = None,
    ) -> int:
        """Read JSON from stdin, evaluate, write response.

        Returns the exit code. IO streams default to ``sys.stdin`` /
        ``sys.stdout`` / ``sys.stderr`` but are injectable for tests.
        """
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        stderr = stderr or sys.stderr

        try:
            raw = stdin.read()
            data = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError as e:
            stderr.write(f"[agentmesh {self.agent_name}] bad json on stdin: {e}\n")
            return 1

        try:
            env = self.normalize_input(data)
        except Exception as e:
            stderr.write(f"[agentmesh {self.agent_name}] normalize error: {e}\n")
            return 1 if not _fail_open() else 0

        try:
            result = self._evaluator.evaluate(env)
        except Exception as e:
            stderr.write(f"[agentmesh {self.agent_name}] evaluator error: {e}\n")
            return 1 if not _fail_open() else 0

        exit_code, out, err = self.format_response(env, result)
        if out:
            stdout.write(out)
            if not out.endswith("\n"):
                stdout.write("\n")
        if err:
            stderr.write(err)
            if not err.endswith("\n"):
                stderr.write("\n")
        return exit_code


__all__ = [
    "ToolCallEnvelope",
    "EvaluationResult",
    "Evaluator",
    "HTTPEvaluator",
    "InProcessEvaluator",
    "AgentHookAdapter",
]
