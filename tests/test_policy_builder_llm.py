"""Tests for the LLM policy proposer endpoint in the proxy."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from agentmesh.proxy import MeshProxy
from tessera.audit_log import (
    JSONLHashchainSink,
    ReplayEnvelope,
    make_replay_detail,
)
from tessera.events import EventKind, SecurityEvent
from tessera.guardrail import LLMGuardrail
from tessera.labels import TrustLevel
from tessera.policy import ResourceType, ToolRequirement
from tessera.replay import iter_replay_cases


SIGNING_KEY = b"test-policy-builder-llm-32bytes!"


def _envelope(*, tool_name="http.post", trust_level=50, decision_allowed=False):
    return ReplayEnvelope(
        trajectory_id="t1",
        tool_name=tool_name,
        args={"url": "https://example.com"},
        segments=[{"trust_level": trust_level, "content_sha256": "abc"}],
        decision_allowed=decision_allowed,
        decision_source="tessera.policy",
        decision_reason="recorded",
    )


def _seed(sink, env, kind=EventKind.POLICY_DENY):
    sink(SecurityEvent(
        kind=kind,
        principal="agent",
        detail=make_replay_detail(env),
        timestamp=datetime.now(timezone.utc).isoformat(),
        correlation_id=None,
        trace_id=None,
    ))


def _mock_client(response_text: str):
    client = MagicMock()
    block = MagicMock()
    block.text = response_text
    response = MagicMock()
    response.content = [block]
    client.messages.create.return_value = response
    return client


def _llm_response(proposals):
    return json.dumps({"proposals": proposals})


def _proxy_with_audit_and_guardrail(tmp_path, llm_response: str):
    proxy = MeshProxy(
        signing_key=SIGNING_KEY,
        audit_log_path=str(tmp_path / "audit.jsonl"),
    )
    proxy._guardrail = LLMGuardrail(
        client=_mock_client(llm_response),
        model="test-model",
    )
    return proxy, TestClient(proxy.build_app())


class TestEndpointGuards:
    def test_unconfigured_without_audit_log(self) -> None:
        proxy = MeshProxy(signing_key=SIGNING_KEY)
        client = TestClient(proxy.build_app())
        data = client.post("/v1/policy/builder/llm", json={}).json()
        assert data["configured"] is False

    def test_llm_unavailable_without_guardrail(self, tmp_path) -> None:
        proxy = MeshProxy(
            signing_key=SIGNING_KEY,
            audit_log_path=str(tmp_path / "audit.jsonl"),
        )
        client = TestClient(proxy.build_app())
        data = client.post("/v1/policy/builder/llm", json={}).json()
        assert data["configured"] is True
        assert data["llm_available"] is False


class TestProposalsAndScoring:
    def test_returns_scored_proposal_end_to_end(self, tmp_path) -> None:
        # The LLM suggests loosening http.post; the audit shows 5 denials
        # at TOOL trust on a USER-required policy. The proposal flips them.
        proxy, client = _proxy_with_audit_and_guardrail(
            tmp_path,
            _llm_response([
                {
                    "kind": "loosen",
                    "tool_name": "http.post",
                    "target_trust": "TOOL",
                    "rationale": "five labeled-incorrect denies",
                    "confidence": 0.9,
                },
            ]),
        )
        proxy._policy.requirements[("http.post", ResourceType.TOOL)] = (
            ToolRequirement(
                name="http.post",
                resource_type=ResourceType.TOOL,
                required_trust=TrustLevel.USER,
                side_effects=True,
            )
        )
        for _ in range(5):
            _seed(proxy._audit_sink, _envelope(
                tool_name="http.post",
                trust_level=int(TrustLevel.TOOL),
                decision_allowed=False,
            ))
        for case in iter_replay_cases(proxy.audit_log_path):
            client.post("/v1/audit/label", json={
                "seq": case.seq,
                "hash": case.record_hash,
                "label": "incorrect",
            })

        data = client.post("/v1/policy/builder/llm", json={"score": True}).json()
        assert data["llm_available"] is True
        assert data["count"] == 1
        prop = data["proposals"][0]
        assert prop["tool_name"] == "http.post"
        assert prop["impact"]["fixed"] == 5
        assert prop["impact"]["regressed"] == 0
        assert prop["impact"]["net_fixes"] == 5

    def test_score_false_skips_replay(self, tmp_path) -> None:
        proxy, client = _proxy_with_audit_and_guardrail(
            tmp_path,
            _llm_response([
                {
                    "kind": "loosen",
                    "tool_name": "http.post",
                    "target_trust": "TOOL",
                    "rationale": "ok",
                    "confidence": 0.9,
                },
            ]),
        )
        for _ in range(3):
            _seed(proxy._audit_sink, _envelope(tool_name="http.post"))
        data = client.post("/v1/policy/builder/llm", json={"score": False}).json()
        assert data["count"] == 1
        assert "impact" not in data["proposals"][0]

    def test_hallucinated_tool_dropped(self, tmp_path) -> None:
        proxy, client = _proxy_with_audit_and_guardrail(
            tmp_path,
            _llm_response([
                {
                    "kind": "loosen",
                    "tool_name": "ghost.fn",
                    "target_trust": "TOOL",
                    "rationale": "imagined",
                    "confidence": 0.5,
                },
            ]),
        )
        for _ in range(3):
            _seed(proxy._audit_sink, _envelope(tool_name="real.fn"))
        data = client.post("/v1/policy/builder/llm", json={"score": False}).json()
        assert data["count"] == 0


class TestMetadata:
    def test_response_includes_breaker_state(self, tmp_path) -> None:
        proxy, client = _proxy_with_audit_and_guardrail(
            tmp_path, _llm_response([]),
        )
        for _ in range(2):
            _seed(proxy._audit_sink, _envelope())
        data = client.post("/v1/policy/builder/llm", json={}).json()
        assert data["breaker_state"] == "closed"
        assert data["model"] == "test-model"
