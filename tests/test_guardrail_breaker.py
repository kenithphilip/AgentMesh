"""Tests for LLMGuardrail circuit-breaker exposure in the proxy."""

from __future__ import annotations

from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from agentmesh.proxy import MeshProxy


def _failing_anthropic_client() -> MagicMock:
    client = MagicMock()
    client.messages.create.side_effect = RuntimeError("provider down")
    return client


def _ok_anthropic_client() -> MagicMock:
    client = MagicMock()
    block = MagicMock()
    block.text = '{"is_injection": false, "confidence": 0.9, "category": "clean"}'
    response = MagicMock()
    response.content = [block]
    client.messages.create.return_value = response
    return client


class TestHealthzBreakerBlock:
    def test_healthz_reports_breaker_when_guardrail_off(self) -> None:
        proxy = MeshProxy(signing_key=b"test-breaker-healthz-32b!!!!!!!!")
        client = TestClient(proxy.build_app())
        r = client.get("/healthz")
        assert r.status_code == 200
        data = r.json()
        assert data["guardrail_enabled"] is False
        assert data["guardrail_breaker"] is None

    def test_healthz_reports_breaker_when_guardrail_on(self) -> None:
        from tessera.guardrail import LLMGuardrail

        proxy = MeshProxy(signing_key=b"test-breaker-healthz-32b!!!!!!!!")
        proxy._guardrail = LLMGuardrail(
            client=_ok_anthropic_client(),
            model="test",
        )
        client = TestClient(proxy.build_app())
        data = client.get("/healthz").json()
        assert data["guardrail_enabled"] is True
        assert data["guardrail_breaker"]["state"] == "closed"
        assert data["guardrail_breaker"]["consecutive_failures"] == 0


class TestMetricsEndpoint:
    def test_disabled_returns_enabled_false(self) -> None:
        proxy = MeshProxy(signing_key=b"test-breaker-metrics-32b!!!!!!!!")
        client = TestClient(proxy.build_app())
        data = client.get("/v1/metrics/guardrail").json()
        assert data == {"enabled": False}

    def test_metrics_reports_call_counts_and_breaker(self) -> None:
        from tessera.guardrail import BreakerConfig, LLMGuardrail

        proxy = MeshProxy(signing_key=b"test-breaker-metrics-32b!!!!!!!!")
        proxy._guardrail = LLMGuardrail(
            client=_failing_anthropic_client(),
            model="test",
            breaker=BreakerConfig(failure_threshold=2),
        )
        # Trip it
        proxy._guardrail.evaluate("a", "tool")
        proxy._guardrail.evaluate("b", "tool")
        # Skipped calls while open
        proxy._guardrail.evaluate("c", "tool")
        proxy._guardrail.evaluate("d", "tool")

        client = TestClient(proxy.build_app())
        data = client.get("/v1/metrics/guardrail").json()
        assert data["enabled"] is True
        assert data["calls"] == 2           # two real calls, both failed
        assert data["skipped_by_breaker"] == 2
        assert data["breaker"]["state"] == "open"
        assert data["breaker"]["total_opens"] == 1
        assert data["breaker"]["total_failures"] == 2
