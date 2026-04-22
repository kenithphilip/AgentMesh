"""Tests for the policy builder endpoint in the proxy."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from agentmesh.proxy import MeshProxy
from tessera.audit_log import (
    JSONLHashchainSink,
    ReplayEnvelope,
    make_replay_detail,
)
from tessera.events import EventKind, SecurityEvent
from tessera.labels import TrustLevel
from tessera.policy import ResourceType, ToolRequirement
from tessera.replay import Label, iter_replay_cases


SIGNING_KEY = b"test-policy-builder-32bytes!!!!!"


def _envelope(
    *,
    tool_name: str = "http.post",
    trust_level: int = 50,  # TrustLevel.TOOL
    decision_allowed: bool = False,
) -> ReplayEnvelope:
    return ReplayEnvelope(
        trajectory_id="t1",
        tool_name=tool_name,
        args={"url": "https://example.com"},
        segments=[{"trust_level": trust_level, "content_sha256": "abc"}],
        decision_allowed=decision_allowed,
        decision_source="tessera.policy",
        decision_reason="recorded",
    )


def _seed(sink: JSONLHashchainSink, env: ReplayEnvelope) -> None:
    sink(SecurityEvent(
        kind=EventKind.POLICY_DENY,
        principal="agent",
        detail=make_replay_detail(env),
        timestamp=datetime.now(timezone.utc).isoformat(),
        correlation_id=None,
        trace_id=None,
    ))


def _proxy(tmp_path) -> tuple[MeshProxy, "TestClient"]:
    proxy = MeshProxy(
        signing_key=SIGNING_KEY,
        audit_log_path=str(tmp_path / "audit.jsonl"),
    )
    return proxy, TestClient(proxy.build_app())


class TestEndpointConfiguration:
    def test_returns_unconfigured_without_audit_log(self) -> None:
        proxy = MeshProxy(signing_key=SIGNING_KEY)
        client = TestClient(proxy.build_app())
        data = client.post("/v1/policy/builder/run", json={}).json()
        assert data["configured"] is False

    def test_returns_empty_when_no_labels(self, tmp_path) -> None:
        proxy, client = _proxy(tmp_path)
        for _ in range(5):
            _seed(proxy._audit_sink, _envelope())
        data = client.post("/v1/policy/builder/run", json={}).json()
        assert data["configured"] is True
        assert data["count"] == 0
        assert data["proposals"] == []


class TestLoosenProposalEndToEnd:
    def test_loosen_proposal_with_full_impact(self, tmp_path) -> None:
        proxy, client = _proxy(tmp_path)
        # Register a strict requirement so denials happen.
        proxy._policy.requirements[("http.post", ResourceType.TOOL)] = (
            ToolRequirement(
                name="http.post",
                resource_type=ResourceType.TOOL,
                required_trust=TrustLevel.USER,
                side_effects=True,
            )
        )
        # Five denials at TOOL level. Loosening to TOOL would let them
        # through.
        for _ in range(5):
            _seed(proxy._audit_sink, _envelope(
                tool_name="http.post",
                trust_level=int(TrustLevel.TOOL),
                decision_allowed=False,
            ))
        # Mark all as INCORRECT.
        for case in iter_replay_cases(proxy.audit_log_path):
            client.post("/v1/audit/label", json={
                "seq": case.seq,
                "hash": case.record_hash,
                "label": "incorrect",
            })

        data = client.post("/v1/policy/builder/run", json={}).json()
        assert data["count"] == 1
        prop = data["proposals"][0]
        assert prop["kind"] == "loosen_requirement"
        assert prop["tool_name"] == "http.post"
        assert prop["current_required_trust"] == "USER"
        assert prop["proposed_required_trust"] == "TOOL"
        assert prop["impact"]["fixed"] == 5
        assert prop["impact"]["regressed"] == 0
        assert prop["impact"]["net_fixes"] == 5
        assert prop["impact"]["flipped_deny_to_allow"] == 5

    def test_no_proposal_below_label_threshold(self, tmp_path) -> None:
        proxy, client = _proxy(tmp_path)
        proxy._policy.requirements[("http.post", ResourceType.TOOL)] = (
            ToolRequirement(
                name="http.post",
                resource_type=ResourceType.TOOL,
                required_trust=TrustLevel.USER,
                side_effects=True,
            )
        )
        for _ in range(2):
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
        # Default min_label_signal is 3; only 2 incorrect denies present.
        data = client.post("/v1/policy/builder/run", json={}).json()
        assert data["count"] == 0


class TestRanking:
    def test_proposals_ranked_by_net_fixes_desc(self, tmp_path) -> None:
        proxy, client = _proxy(tmp_path)
        for tool in ("small", "big"):
            proxy._policy.requirements[(tool, ResourceType.TOOL)] = (
                ToolRequirement(
                    name=tool,
                    resource_type=ResourceType.TOOL,
                    required_trust=TrustLevel.USER,
                    side_effects=True,
                )
            )
        for _ in range(3):
            _seed(proxy._audit_sink, _envelope(
                tool_name="small",
                trust_level=int(TrustLevel.TOOL),
                decision_allowed=False,
            ))
        for _ in range(7):
            _seed(proxy._audit_sink, _envelope(
                tool_name="big",
                trust_level=int(TrustLevel.TOOL),
                decision_allowed=False,
            ))
        for case in iter_replay_cases(proxy.audit_log_path):
            client.post("/v1/audit/label", json={
                "seq": case.seq,
                "hash": case.record_hash,
                "label": "incorrect",
            })

        data = client.post("/v1/policy/builder/run", json={}).json()
        assert data["count"] == 2
        names = [p["tool_name"] for p in data["proposals"]]
        assert names == ["big", "small"]
        assert data["proposals"][0]["impact"]["net_fixes"] == 7
        assert data["proposals"][1]["impact"]["net_fixes"] == 3
