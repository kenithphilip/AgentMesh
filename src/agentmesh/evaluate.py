"""agentmesh.evaluate

Reference ``ToolCallEvaluator`` showing the correct layer ordering.

This is a pure reference: the production proxy in ``agentmesh.proxy``
already composes these layers into one ``MeshProxy.evaluate_tool_call``.
Use ``ToolCallEvaluator`` when embedding the mesh primitives directly
in another application without running the proxy.

Ordering rationale
------------------
1. destructive_guard       Cheap pattern match, explicit deny, highest
                           audit signal. Runs first so the audit log
                           attributes denies to a named pattern id, not
                           a scanner threshold.
2. sensitivity / outbound  Pure read of the trajectory HWM. Reproducible
                           from audit data. No scanning cost.
3. existing scanners       Directive / intent / heuristic live where
                           false-positive tuning happens.
4. irreversibility scorer  Numeric. Runs last so its float verdicts do
                           not pre-empt the deterministic layers above.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from tessera.destructive_guard import DestructiveGuard, GuardResult
from tessera.sensitivity import (
    HighWaterMark,
    OutboundDecision,
    OutboundPolicy,
    SensitivityLabel,
)


@dataclass
class Decision:
    allowed: bool
    reason: str
    source: str
    metadata: dict[str, Any]

    @classmethod
    def allow(cls, source: str = "agentmesh", **md: Any) -> "Decision":
        return cls(allowed=True, reason="ok", source=source, metadata=md)

    @classmethod
    def deny(cls, *, reason: str, source: str, **md: Any) -> "Decision":
        return cls(allowed=False, reason=reason, source=source, metadata=md)


class ToolCallEvaluator:
    """Compose destructive + sensitivity + (your scanners) into one call.

    Args:
        destructive_guard: The pattern deny-list.
        outbound_policy: OutboundPolicy with your tool registry.
        hwm: HighWaterMark backing store.
        directive_scanner, intent_scanner, heuristic_scanner: Optional
            existing Tessera scanners. Each should expose a
            ``scan(tool_name, args, trajectory_id) -> Result`` with
            ``.allowed``, ``.reason``, ``.metadata``.
        irreversibility_scorer: Optional scorer returning a float in
            [0, 1]. Called last; deny if the score exceeds the threshold.
        irreversibility_threshold: Denies above this.
    """

    def __init__(
        self,
        destructive_guard: DestructiveGuard,
        outbound_policy: OutboundPolicy,
        hwm: HighWaterMark,
        directive_scanner: Any = None,
        intent_scanner: Any = None,
        heuristic_scanner: Any = None,
        irreversibility_scorer: Any = None,
        irreversibility_threshold: float = 0.85,
    ) -> None:
        self.destructive_guard = destructive_guard
        self.outbound_policy = outbound_policy
        self.hwm = hwm
        self.directive_scanner = directive_scanner
        self.intent_scanner = intent_scanner
        self.heuristic_scanner = heuristic_scanner
        self.irreversibility_scorer = irreversibility_scorer
        self.irreversibility_threshold = irreversibility_threshold

    def evaluate_tool_call(
        self,
        *,
        trajectory_id: str,
        tool_name: str,
        args: Mapping[str, Any] | str | None,
    ) -> Decision:
        # 1. destructive_guard
        dg: GuardResult = self.destructive_guard.check(tool_name, args)
        if not dg.allowed:
            m = dg.matches[0]
            return Decision.deny(
                reason=dg.primary_reason,
                source=dg.source,
                pattern_id=m.pattern_id,
                category=m.category,
                arg_path=m.arg_path,
                matched_text=m.matched_text,
            )

        # 2. sensitivity / outbound
        current_hwm: SensitivityLabel = self.hwm.get(trajectory_id)
        od: OutboundDecision = self.outbound_policy.check(tool_name, current_hwm)
        if not od.allowed:
            return Decision.deny(
                reason=od.reason,
                source=od.source,
                hwm=od.hwm.name,
                hwm_rank=int(od.hwm),
                tool_max=od.tool_max.name,
                tool_max_rank=int(od.tool_max),
            )

        # 3. existing scanners (optional hooks)
        for scanner, name in (
            (self.directive_scanner, "directive"),
            (self.intent_scanner, "intent"),
            (self.heuristic_scanner, "heuristic"),
        ):
            if scanner is None:
                continue
            r = scanner.scan(tool_name=tool_name, args=args, trajectory_id=trajectory_id)
            if not getattr(r, "allowed", True):
                return Decision.deny(
                    reason=getattr(r, "reason", f"denied by {name}"),
                    source=f"tessera.scanners.{name}",
                    **getattr(r, "metadata", {}),
                )

        # 4. irreversibility scorer
        if self.irreversibility_scorer is not None:
            score = self.irreversibility_scorer.score(
                tool_name=tool_name, args=args,
            )
            if score >= self.irreversibility_threshold:
                return Decision.deny(
                    reason=(
                        f"irreversibility score {score:.2f} >= "
                        f"{self.irreversibility_threshold}"
                    ),
                    source="tessera.risk.irreversibility",
                    score=score,
                )

        return Decision.allow(
            source="agentmesh",
            hwm=current_hwm.name,
            hwm_rank=int(current_hwm),
        )


__all__ = ["Decision", "ToolCallEvaluator"]
