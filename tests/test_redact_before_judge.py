"""Tests for guardrail_redact_before_judge mode in the proxy.

The flag controls whether the LLM judge sees the post-redaction or
pre-redaction form of a tool output. Default is post-redaction
(secrets and PII replaced with placeholders) so the judge endpoint
never sees raw secrets.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from agentmesh.proxy import MeshProxy


SIGNING_KEY = b"test-redact-judge-32bytes!!!!!!!"
SECRET_VALUE = "sk-livesecret-12345"


def _ok_anthropic_client() -> MagicMock:
    """Mock client that returns a clean classification.

    The point of this test is the input the client SEES, not the verdict.
    """
    client = MagicMock()
    block = MagicMock()
    block.text = '{"is_injection": false, "confidence": 0.9, "category": "clean"}'
    response = MagicMock()
    response.content = [block]
    client.messages.create.return_value = response
    return client


def _proxy_with_secret(*, redact_before_judge: bool = True) -> tuple[MeshProxy, MagicMock]:
    proxy = MeshProxy(
        signing_key=SIGNING_KEY,
        guardrail_redact_before_judge=redact_before_judge,
    )
    proxy.register_secret("LIVE_KEY", SECRET_VALUE)
    # Wire a real guardrail with a mocked client so we can inspect the
    # text it received via the mock call args.
    from tessera.guardrail import LLMGuardrail
    client = _ok_anthropic_client()
    proxy._guardrail = LLMGuardrail(client=client, model="test")
    return proxy, client


def _judge_input(client: MagicMock) -> str:
    """The user message the proxy passed to the judge LLM."""
    assert client.messages.create.call_count >= 1
    call = client.messages.create.call_args
    msg = call.kwargs["messages"][0]["content"]
    return msg


class TestRedactBeforeJudgeDefault:
    def test_secret_is_scrubbed_before_judge_sees_it(self) -> None:
        """Default behavior: judge sees [REDACTED:...] placeholder."""
        proxy, client = _proxy_with_secret(redact_before_judge=True)
        # A plain free-text tool, ambiguous enough to skip the
        # deterministic short-circuit.
        proxy.scan_and_label(
            "read_file",
            f"Random note: {SECRET_VALUE} appears here once.",
        )
        seen = _judge_input(client)
        assert SECRET_VALUE not in seen
        # Redaction marker is present in the redacted form.
        assert "<REDACTED:LIVE_KEY>" in seen


class TestRedactBeforeJudgeOptOut:
    def test_secret_reaches_judge_when_opted_out(self) -> None:
        """Opt-out: judge sees the raw text including the secret."""
        proxy, client = _proxy_with_secret(redact_before_judge=False)
        proxy.scan_and_label(
            "read_file",
            f"Random note: {SECRET_VALUE} appears here once.",
        )
        seen = _judge_input(client)
        assert SECRET_VALUE in seen
        assert "<REDACTED:LIVE_KEY>" not in seen


class TestEventReflectsMode:
    def _capture(self):
        from tessera.events import register_sink, unregister_sink, SecurityEvent
        captured: list[SecurityEvent] = []
        register_sink(captured.append)
        return captured, lambda: unregister_sink(captured.append)

    def test_event_records_redacted_true_by_default(self) -> None:
        proxy, _ = _proxy_with_secret(redact_before_judge=True)
        captured, undo = self._capture()
        try:
            proxy.scan_and_label("read_file", f"note {SECRET_VALUE}")
        finally:
            undo()
        decisions = [
            e for e in captured if e.detail.get("scanner") == "llm_guardrail"
        ]
        assert decisions
        assert decisions[-1].detail["redacted_input"] is True

    def test_event_records_redacted_false_when_opted_out(self) -> None:
        proxy, _ = _proxy_with_secret(redact_before_judge=False)
        captured, undo = self._capture()
        try:
            proxy.scan_and_label("read_file", f"note {SECRET_VALUE}")
        finally:
            undo()
        decisions = [
            e for e in captured if e.detail.get("scanner") == "llm_guardrail"
        ]
        assert decisions
        assert decisions[-1].detail["redacted_input"] is False
