"""Tests for replay/scoring endpoints in the proxy."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from agentmesh.proxy import MeshProxy
from tessera.audit_log import JSONLHashchainSink, ReplayEnvelope, make_replay_detail
from tessera.events import EventKind, SecurityEvent


SIGNING_KEY = b"test-replay-32bytes!!!!!!!!!!!!!"


def _seed_audit(
    sink: JSONLHashchainSink,
    *,
    tool_name: str = "http.post",
    trust_level: int = 0,
    decision_allowed: bool = False,
    trajectory_id: str = "t1",
    kind: EventKind = EventKind.POLICY_DENY,
) -> None:
    envelope = ReplayEnvelope(
        trajectory_id=trajectory_id,
        tool_name=tool_name,
        args={"url": "https://example.com"},
        segments=[{"trust_level": trust_level, "content_sha256": "abc"}],
        decision_allowed=decision_allowed,
        decision_source="tessera.policy",
        decision_reason="recorded",
    )
    sink(SecurityEvent(
        kind=kind,
        principal="agent",
        detail=make_replay_detail(envelope),
        timestamp=datetime.now(timezone.utc).isoformat(),
        correlation_id=None,
        trace_id=None,
    ))


def _proxy_with_audit(tmp_path) -> tuple[MeshProxy, "TestClient"]:
    audit_path = tmp_path / "audit.jsonl"
    proxy = MeshProxy(
        signing_key=SIGNING_KEY,
        audit_log_path=str(audit_path),
    )
    client = TestClient(proxy.build_app())
    return proxy, client


class TestAuditCases:
    def test_lists_cases(self, tmp_path) -> None:
        proxy, client = _proxy_with_audit(tmp_path)
        _seed_audit(proxy._audit_sink, trajectory_id="a")
        _seed_audit(proxy._audit_sink, trajectory_id="b")

        r = client.get("/v1/audit/cases")
        assert r.status_code == 200
        data = r.json()
        assert data["configured"] is True
        assert data["count"] == 2
        traj = [c["trajectory_id"] for c in data["cases"]]
        assert sorted(traj) == ["a", "b"]
        assert all(c["label"] == "unreviewed" for c in data["cases"])

    def test_filters_by_trajectory(self, tmp_path) -> None:
        proxy, client = _proxy_with_audit(tmp_path)
        _seed_audit(proxy._audit_sink, trajectory_id="keep")
        _seed_audit(proxy._audit_sink, trajectory_id="drop")

        r = client.get("/v1/audit/cases?trajectory_id=keep")
        data = r.json()
        assert data["count"] == 1
        assert data["cases"][0]["trajectory_id"] == "keep"

    def test_no_audit_log_returns_unconfigured(self) -> None:
        proxy = MeshProxy(signing_key=SIGNING_KEY)
        client = TestClient(proxy.build_app())
        data = client.get("/v1/audit/cases").json()
        assert data["configured"] is False
        assert data["cases"] == []


class TestAuditLabels:
    def test_set_and_list(self, tmp_path) -> None:
        proxy, client = _proxy_with_audit(tmp_path)
        _seed_audit(proxy._audit_sink)
        case = client.get("/v1/audit/cases").json()["cases"][0]

        r = client.post("/v1/audit/label", json={
            "seq": case["seq"],
            "hash": case["hash"],
            "label": "incorrect",
        })
        assert r.status_code == 200
        assert r.json()["label"] == "incorrect"

        labels = client.get("/v1/audit/labels").json()
        assert labels["labels"][str(case["seq"])]["label"] == "incorrect"

    def test_label_persists_to_disk(self, tmp_path) -> None:
        proxy, client = _proxy_with_audit(tmp_path)
        _seed_audit(proxy._audit_sink)
        case = client.get("/v1/audit/cases").json()["cases"][0]
        client.post("/v1/audit/label", json={
            "seq": case["seq"],
            "hash": case["hash"],
            "label": "correct",
        })
        # Reopen the proxy on the same paths.
        proxy2 = MeshProxy(
            signing_key=SIGNING_KEY,
            audit_log_path=str(tmp_path / "audit.jsonl"),
        )
        client2 = TestClient(proxy2.build_app())
        labels = client2.get("/v1/audit/labels").json()
        assert labels["labels"][str(case["seq"])]["label"] == "correct"

    def test_invalid_label_returns_error(self, tmp_path) -> None:
        proxy, client = _proxy_with_audit(tmp_path)
        _seed_audit(proxy._audit_sink)
        case = client.get("/v1/audit/cases").json()["cases"][0]
        r = client.post("/v1/audit/label", json={
            "seq": case["seq"],
            "hash": case["hash"],
            "label": "bogus",
        })
        assert "error" in r.json()


class TestReplayRun:
    def test_current_policy_agrees_when_taint_floor_holds(self, tmp_path) -> None:
        # Original deny on UNTRUSTED context for a side-effecting tool.
        # The proxy's default Policy still denies, so replay agrees.
        proxy, client = _proxy_with_audit(tmp_path)
        _seed_audit(
            proxy._audit_sink,
            tool_name="http.post",
            trust_level=0,           # UNTRUSTED
            decision_allowed=False,
        )
        r = client.post("/v1/replay/run", json={"candidate": "current_policy"})
        assert r.status_code == 200
        data = r.json()
        assert data["stats"]["total"] == 1
        assert data["stats"]["agreed"] == 1
        assert data["results"][0]["agreement"] == "agreed"

    def test_unknown_candidate_returns_error(self, tmp_path) -> None:
        proxy, client = _proxy_with_audit(tmp_path)
        _seed_audit(proxy._audit_sink)
        r = client.post("/v1/replay/run", json={"candidate": "nope"})
        data = r.json()
        assert "error" in data
        assert "current_policy" in data["available"]

    def test_no_audit_log_returns_unconfigured(self) -> None:
        proxy = MeshProxy(signing_key=SIGNING_KEY)
        client = TestClient(proxy.build_app())
        data = client.post("/v1/replay/run", json={}).json()
        assert data["configured"] is False

    def test_labels_drive_fixed_regressed(self, tmp_path) -> None:
        # Original allow that the current policy will deny (UNTRUSTED + side
        # effects). Marking the original as incorrect makes the flip a "fix".
        proxy, client = _proxy_with_audit(tmp_path)
        _seed_audit(
            proxy._audit_sink,
            tool_name="http.post",
            trust_level=0,
            decision_allowed=True,   # original was a (wrong) allow
        )
        case = client.get("/v1/audit/cases").json()["cases"][0]
        client.post("/v1/audit/label", json={
            "seq": case["seq"],
            "hash": case["hash"],
            "label": "incorrect",
        })
        data = client.post("/v1/replay/run", json={}).json()
        assert data["stats"]["disagreed"] == 1
        assert data["stats"]["flipped_allow_to_deny"] == 1
        assert data["stats"]["fixed"] == 1
        assert data["stats"]["regressed"] == 0


class TestReplayCandidates:
    def test_lists_built_in_candidates(self, tmp_path) -> None:
        proxy, client = _proxy_with_audit(tmp_path)
        data = client.get("/v1/replay/candidates").json()
        names = [c["name"] for c in data["candidates"]]
        assert "current_policy" in names
