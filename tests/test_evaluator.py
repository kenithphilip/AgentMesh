"""Tests for agentmesh.evaluate.ToolCallEvaluator layer ordering."""

from __future__ import annotations

from tessera.destructive_guard import DestructiveGuard
from tessera.sensitivity import (
    HighWaterMark,
    OutboundPolicy,
    SensitivityLabel,
    ToolClassification,
)

from agentmesh.evaluate import Decision, ToolCallEvaluator


class TestLayerOrdering:
    def test_destructive_wins_over_sensitivity(self) -> None:
        """When a call is both destructive AND would leak confidential
        data, the audit log must attribute the deny to the destructive
        pattern, not to the sensitivity layer.
        """
        hwm = HighWaterMark()
        hwm.observe("t1", SensitivityLabel.CONFIDENTIAL)
        ev = ToolCallEvaluator(
            destructive_guard=DestructiveGuard(),
            outbound_policy=OutboundPolicy(
                registry={
                    "http.post": ToolClassification(
                        outbound=True,
                        max_sensitivity=SensitivityLabel.INTERNAL,
                    ),
                },
            ),
            hwm=hwm,
        )
        d = ev.evaluate_tool_call(
            trajectory_id="t1",
            tool_name="http.post",
            args={"body": "DROP TABLE users;"},
        )
        assert not d.allowed
        assert d.source == "tessera.destructive_guard"
        assert d.metadata["pattern_id"] == "sql.drop_table"

    def test_sensitivity_fires_when_not_destructive(self) -> None:
        hwm = HighWaterMark()
        hwm.observe("t1", SensitivityLabel.CONFIDENTIAL)
        ev = ToolCallEvaluator(
            destructive_guard=DestructiveGuard(),
            outbound_policy=OutboundPolicy(
                registry={
                    "http.post": ToolClassification(
                        outbound=True,
                        max_sensitivity=SensitivityLabel.INTERNAL,
                    ),
                },
            ),
            hwm=hwm,
        )
        d = ev.evaluate_tool_call(
            trajectory_id="t1",
            tool_name="http.post",
            args={"body": "hello"},
        )
        assert not d.allowed
        assert d.source == "tessera.sensitivity"
        assert d.metadata["hwm"] == "CONFIDENTIAL"
        assert d.metadata["tool_max"] == "INTERNAL"

    def test_clean_call_allowed(self) -> None:
        hwm = HighWaterMark()
        ev = ToolCallEvaluator(
            destructive_guard=DestructiveGuard(),
            outbound_policy=OutboundPolicy(),
            hwm=hwm,
        )
        d = ev.evaluate_tool_call(
            trajectory_id="t1",
            tool_name="fs.read",
            args={"path": "./report.txt"},
        )
        assert d.allowed
        assert d.source == "agentmesh"

    def test_irreversibility_runs_last(self) -> None:
        class FakeScorer:
            def score(self, *, tool_name: str, args: object) -> float:
                return 0.95

        hwm = HighWaterMark()
        ev = ToolCallEvaluator(
            destructive_guard=DestructiveGuard(),
            outbound_policy=OutboundPolicy(),
            hwm=hwm,
            irreversibility_scorer=FakeScorer(),
            irreversibility_threshold=0.85,
        )
        d = ev.evaluate_tool_call(
            trajectory_id="t1",
            tool_name="fs.write",
            args={"path": "./report.txt", "content": "hi"},
        )
        assert not d.allowed
        assert d.source == "tessera.risk.irreversibility"
        assert d.metadata["score"] == 0.95

    def test_destructive_beats_irreversibility(self) -> None:
        """Destructive deny should fire before the irreversibility scorer."""
        class FakeScorer:
            def score(self, *, tool_name: str, args: object) -> float:
                return 0.99

        hwm = HighWaterMark()
        ev = ToolCallEvaluator(
            destructive_guard=DestructiveGuard(),
            outbound_policy=OutboundPolicy(),
            hwm=hwm,
            irreversibility_scorer=FakeScorer(),
        )
        d = ev.evaluate_tool_call(
            trajectory_id="t1",
            tool_name="bash.run",
            args={"command": "rm -rf /"},
        )
        assert not d.allowed
        assert d.source == "tessera.destructive_guard"
        assert d.metadata["pattern_id"] == "fs.rm_rf_root"
