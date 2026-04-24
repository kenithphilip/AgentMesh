"""tessera_rs adapter shims for AgentMesh.

When ``MeshProxy(use_rust_primitives=True)`` is set and the
``tessera-rs`` PyPI wheel is installed, AgentMesh swaps a curated
subset of its hot-path primitives to the Rust implementations. This
module bridges the Python ``tessera`` API surface AgentMesh's proxy
expects to the surface ``tessera_rs`` actually exposes.

Adapters provided:

- :class:`RustPolicyAdapter` for ``tessera.policy.Policy``
- :class:`RustContextAdapter` for ``tessera.context.Context``
- :class:`RustJsonlHashchainSinkAdapter` for
  ``tessera.audit_log.JSONLHashchainSink``
- :class:`RustSsrfGuardAdapter` for ``tessera.ssrf_guard.SSRFGuard``
- :class:`RustUrlRulesEngineAdapter` for
  ``tessera.url_rules.URLRulesEngine``
- :class:`RustCelPolicyEngineAdapter` for
  ``tessera.cel_engine.CELPolicyEngine``
- :func:`rust_canonical_json` for
  ``tessera.audit_log.canonical_json``
- :func:`rust_injection_score` for
  ``tessera.scanners.heuristic.injection_score``
- :func:`rust_scan_unicode_tags` for
  ``tessera.scanners.unicode.scan_unicode_tags``

The adapters fall back to the Python implementation transparently
for surfaces tessera_rs does not yet cover (delegation tokens, full
``Policy.merge``, scanner pipelines beyond heuristic + unicode,
etc.). See ``docs/RUST_PRIMITIVES.md`` for the full unsupported
surface map.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

logger = logging.getLogger(__name__)


class _TesseraRsBundle:
    """Tiny holder for the tessera_rs submodules we use.

    The PyO3 wheel exposes its surface as ``tessera_rs.policy``,
    ``tessera_rs.context``, etc. ``import tessera_rs`` does not
    trigger the submodule imports automatically (they are pure-
    Python shims around ``tessera_rs._native``), so we eagerly
    import them once at module load.
    """

    def __init__(self) -> None:
        import tessera_rs as core
        from tessera_rs import audit, cel, context, policy, scanners, ssrf, url_rules

        self.core = core
        self.audit = audit
        self.cel = cel
        self.context = context
        self.policy = policy
        self.scanners = scanners
        self.ssrf = ssrf
        self.url_rules = url_rules


def _try_import_tessera_rs() -> _TesseraRsBundle | None:
    """Return a :class:`_TesseraRsBundle` or ``None`` if absent.

    Returns ``None`` on ``ImportError`` so callers can short-circuit
    gracefully when the wheel is not installed.
    """
    try:
        return _TesseraRsBundle()
    except ImportError:
        return None


_BUNDLE: _TesseraRsBundle | None = _try_import_tessera_rs()
TESSERA_RS_AVAILABLE: bool = _BUNDLE is not None
"""``True`` when the ``tessera-rs`` PyPI wheel is importable."""


def require_tessera_rs() -> _TesseraRsBundle:
    """Return the bundle of ``tessera_rs`` submodules or raise."""
    if _BUNDLE is None:
        raise RuntimeError(
            "tessera-rs is not installed. "
            "Install with: pip install tessera-rs (>=0.10.0a1)"
        )
    return _BUNDLE


# ---------------------------------------------------------------------------
# Origin / TrustLevel translation
# ---------------------------------------------------------------------------


def _origin_to_str(origin: Any) -> str:
    """Translate a Python ``tessera.labels.Origin`` into the lowercase
    string form ``tessera_rs.context.Context.add_segment`` accepts.

    Handles both the ``Origin`` enum (``Origin.WEB``) and a plain
    string (``"web"``). Defaults to ``"tool"`` for unknown values
    rather than raising; the Rust side rejects values it does not
    recognize, which surfaces as a clean ``ValueError``.
    """
    if hasattr(origin, "name"):  # tessera.labels.Origin enum
        return str(origin.name).lower()
    if hasattr(origin, "value"):
        return str(origin.value).lower()
    if isinstance(origin, str):
        return origin.lower()
    return "tool"


def _trust_level_to_int(level: Any) -> int:
    """Translate a Python ``TrustLevel`` (IntEnum-like) into the ``int``
    ``tessera_rs`` expects. Falls back to ``0`` for unknown values."""
    if hasattr(level, "value"):
        return int(level.value)
    if isinstance(level, int):
        return int(level)
    return 0


# ---------------------------------------------------------------------------
# Context adapter
# ---------------------------------------------------------------------------


class RustContextAdapter:
    """Drop-in for ``tessera.context.Context`` backed by Rust.

    Exposes ``add(segment)`` and ``min_trust`` so AgentMesh's
    existing proxy code continues to work. The wrapped Rust
    ``Context`` requires a 32-byte signing key; the adapter takes
    one at construction time.

    Limitations: the Rust ``Context`` does not currently expose
    iterating segments or the rich ``LabeledSegment`` shape
    (origin, principal, label hash) that some AgentMesh code
    paths read. Those code paths still need the Python
    ``Context``; the adapter logs a warning when a missing
    attribute is accessed.
    """

    def __init__(self, signing_key: bytes) -> None:
        rs = require_tessera_rs()
        if len(signing_key) < 32:
            signing_key = signing_key.ljust(32, b"\x00")
        self._inner = rs.context.Context(signing_key=signing_key)

    def add(self, segment: Any) -> None:
        """Mirror Python ``Context.add(segment)``.

        ``segment`` is a Python ``LabeledSegment`` with ``content``,
        ``label`` (with ``.origin``, ``.principal``, ``.trust_level``).
        We unpack to the four fields the Rust binding accepts.
        """
        content = getattr(segment, "content", None) or getattr(segment, "text", "")
        label = getattr(segment, "label", segment)
        origin = _origin_to_str(getattr(label, "origin", "tool"))
        principal = getattr(label, "principal", "")
        trust_level = _trust_level_to_int(getattr(label, "trust_level", 0))
        self._inner.add_segment(
            content=content,
            origin=origin,
            principal=str(principal),
            trust_level=trust_level,
        )

    @property
    def min_trust(self) -> int:
        return int(self._inner.min_trust)

    @property
    def segment_count(self) -> int:
        return int(self._inner.segment_count)

    def __len__(self) -> int:
        return self.segment_count


# ---------------------------------------------------------------------------
# Policy adapter
# ---------------------------------------------------------------------------


@dataclass
class _PolicyDecisionShim:
    """Lightweight stand-in for ``tessera.policy.Decision``.

    Tessera's Python ``Decision`` is an attrs/dataclass with several
    fields; we mirror the ones AgentMesh's proxy reads.
    """

    allowed: bool
    kind: str
    reason: str
    tool: str
    required_trust: int
    observed_trust: int

    @property
    def allow(self) -> bool:
        return self.allowed


class RustPolicyAdapter:
    """Drop-in for ``tessera.policy.Policy`` backed by Rust.

    Hot path: ``evaluate(context, tool_name, args=None, principal='',
    delegation=None)`` calls the Rust ``Policy.evaluate_with_cel`` if
    a CEL engine is installed, else the plain ``Policy.evaluate``.
    Returns a :class:`_PolicyDecisionShim` shaped like the Python
    ``Decision``.

    Cold path (registration, merge, deny rules): falls back to a
    Python ``tessera.policy.Policy`` instance held alongside the Rust
    one. This avoids re-implementing the YAML loader, hierarchical
    merge, and other rarely-called surfaces.
    """

    def __init__(self) -> None:
        rs = require_tessera_rs()
        self._rust = rs.policy.Policy()
        # Lazily constructed Python fallback for cold-path methods.
        self._python: Any | None = None

    def _get_python(self) -> Any:
        if self._python is None:
            from tessera.policy import Policy as PyPolicy

            self._python = PyPolicy()
        return self._python

    # ---- Tool registration (forwards to BOTH backends) -----------------

    def require(
        self,
        name: str,
        level: Any,
        resource_type: Any = None,
        side_effects: bool = True,
    ) -> None:
        """Register a tool requirement on both backends.

        Mirrors the Python ``Policy.require(name, level, ...)``
        signature. The Rust policy only consumes (name, level: int)
        for tool-type requirements; non-tool resource types and
        non-side-effecting tools fall back to the Python policy
        being authoritative for that requirement.
        """
        py = self._get_python()
        if resource_type is not None:
            py.require(name, level, resource_type=resource_type, side_effects=side_effects)
        else:
            py.require(name, level, side_effects=side_effects)
        # Rust side: only tools, only side-effecting (matching Rust
        # require_tool semantics).
        if resource_type is None and side_effects:
            self._rust.require_tool(str(name), _trust_level_to_int(level))

    def require_tool(self, name: str, level: Any) -> None:
        """Convenience: ``require(name, level)`` for tool-type."""
        self.require(name, level)

    def require_human_approval(self, tool: str) -> None:
        # Rust side has no equivalent yet; keep Python authoritative.
        self._get_python().require_human_approval(tool)

    def requires_human_approval(self, tool: str) -> bool:
        return bool(self._get_python().requires_human_approval(tool))

    # ---- CEL engine wiring --------------------------------------------

    def set_cel_engine(self, engine: Any) -> None:
        """Install a CEL engine.

        Accepts either a :class:`RustCelPolicyEngineAdapter` (preferred,
        keeps the whole hot path on Rust) or a Python
        ``CELPolicyEngine`` (compiled rules are forwarded into a fresh
        Rust engine; rule introspection still works because the
        adapter retains the originals).
        """
        if engine is None:
            self._rust.set_cel_engine(None)
            return
        if isinstance(engine, RustCelPolicyEngineAdapter):
            self._rust.set_cel_engine(engine._inner)
            return
        # Python CELPolicyEngine: rebuild rules on the Rust side.
        rs = require_tessera_rs()
        rust_rules = []
        for rule in getattr(engine, "_rules", []):
            rust_rules.append(
                rs.cel.CelRule(
                    name=rule.name,
                    expression=rule.expression,
                    action=rule.action,
                    message=rule.message,
                )
            )
        self._rust.set_cel_engine(rs.cel.CelPolicyEngine(rust_rules))

    @property
    def cel_engine(self) -> Any | None:
        # AgentMesh sometimes reads `policy.cel_engine._rules` to
        # surface the active rule set on /v1/policy. We do not
        # currently expose the engine handle from the Rust side via
        # PyO3; return the Python fallback's value if any.
        return getattr(self._get_python(), "cel_engine", None)

    # ---- Hot-path evaluate --------------------------------------------

    def evaluate(
        self,
        context: Any,
        tool_name: str,
        args: dict[str, Any] | None = None,
        principal: str = "",
        delegation: Any = None,
        expected_delegate: Any = None,
    ) -> _PolicyDecisionShim:
        """Evaluate against the taint floor + (optional) CEL layer.

        Mirrors the Python ``Policy.evaluate`` signature. Delegation
        verification is out of scope for the Rust hot path; the
        adapter passes the delegation subject and actions through to
        the CEL activation (mirroring Python's behavior) but does not
        verify the delegation token here.
        """
        ctx = self._unwrap_context(context)
        # Stringify args for Python parity (matches CelContext quirk).
        args_str = {
            str(k): str(v) for k, v in (args or {}).items()
        }
        delegation_subject = None
        delegation_actions: list[str] = []
        if delegation is not None:
            delegation_subject = getattr(delegation, "subject", None)
            actions = getattr(delegation, "actions", None) or ()
            delegation_actions = [str(a) for a in actions]

        result = self._rust.evaluate_with_cel(
            ctx,
            tool_name,
            args=args_str,
            principal=str(principal),
            delegation_subject=delegation_subject,
            delegation_actions=delegation_actions,
        )
        return _PolicyDecisionShim(
            allowed=bool(result["allowed"]),
            kind=str(result["kind"]),
            reason=str(result["reason"]),
            tool=str(result["tool"]),
            required_trust=int(result["required_trust"]),
            observed_trust=int(result["observed_trust"]),
        )

    @staticmethod
    def _unwrap_context(context: Any) -> Any:
        """Return the inner ``tessera_rs`` context.

        Accepts either a :class:`RustContextAdapter` or a raw Rust
        ``Context``. Raises ``TypeError`` for an unwrapped Python
        ``Context`` so the caller knows to wrap first.
        """
        if isinstance(context, RustContextAdapter):
            return context._inner
        # Detect the raw Rust class by attribute presence.
        if hasattr(context, "add_segment") and hasattr(context, "min_trust"):
            return context
        raise TypeError(
            "RustPolicyAdapter.evaluate requires a RustContextAdapter "
            "or tessera_rs Context, got "
            f"{type(context).__name__}. Wrap with RustContextAdapter first."
        )

    # ---- Rarely used surfaces (forward to Python) ---------------------

    def merge(self, other: Any) -> None:
        self._get_python().merge(other)

    def requirements_count(self) -> int:
        return int(self._get_python().requirements_count())


# ---------------------------------------------------------------------------
# Audit sink adapter
# ---------------------------------------------------------------------------


class RustJsonlHashchainSinkAdapter:
    """Drop-in for ``tessera.audit_log.JSONLHashchainSink``.

    Constructor signature matches Python: ``(path, fsync_every=1,
    seal_key=None)``. The ``append(event)`` method accepts a Python
    ``SecurityEvent`` (or any object with ``timestamp``, ``kind``,
    ``principal``, ``detail``, ``correlation_id``, ``trace_id``)
    and forwards to the Rust binding.
    """

    def __init__(
        self,
        path: str,
        fsync_every: int = 1,
        seal_key: bytes | None = None,
    ) -> None:
        rs = require_tessera_rs()
        self._inner = rs.audit.JsonlHashchainSink(
            path=path,
            fsync_every=int(fsync_every),
            seal_key=seal_key,
        )

    def append(self, event: Any) -> int:
        timestamp = getattr(event, "timestamp", "")
        kind = getattr(event, "kind", "")
        principal = getattr(event, "principal", "")
        detail = getattr(event, "detail", {}) or {}
        correlation_id = getattr(event, "correlation_id", None)
        trace_id = getattr(event, "trace_id", None)
        # Rust expects detail as a JSON string (canonicalized later).
        if isinstance(detail, dict):
            detail_json = json.dumps(detail, sort_keys=True, separators=(",", ":"))
        else:
            detail_json = json.dumps(detail)
        return int(
            self._inner.append(
                timestamp=str(timestamp),
                kind=str(kind),
                principal=str(principal),
                detail_json=detail_json,
                correlation_id=correlation_id,
                trace_id=trace_id,
            )
        )

    def flush(self) -> None:
        """Block until the writer thread has drained every queued append."""
        self._inner.flush()


def rust_canonical_json(value: dict | list | Any) -> str:
    """Drop-in for ``tessera.audit_log.canonical_json``.

    The Python helper takes a Python value; the Rust binding takes a
    JSON string. This shim handles the conversion so callers do not
    need to know the difference.
    """
    rs = require_tessera_rs()
    return str(rs.audit.canonical_json(json.dumps(value)))


# ---------------------------------------------------------------------------
# Scanner adapters
# ---------------------------------------------------------------------------


def rust_injection_score(text: str) -> float:
    """Drop-in for ``tessera.scanners.heuristic.injection_score``."""
    rs = require_tessera_rs()
    return float(rs.scanners.injection_score(text))


@dataclass(frozen=True)
class _UnicodeScanResultShim:
    """Mirror of ``tessera.scanners.unicode.UnicodeScanResult``."""

    detected: bool
    hidden_payload: str
    tag_count: int
    positions: tuple[int, ...]


def rust_scan_unicode_tags(text: str) -> _UnicodeScanResultShim:
    """Drop-in for ``tessera.scanners.unicode.scan_unicode_tags``."""
    rs = require_tessera_rs()
    raw = rs.scanners.scan_unicode_tags(text)
    return _UnicodeScanResultShim(
        detected=bool(raw["detected"]),
        hidden_payload=str(raw["hidden_payload"]),
        tag_count=int(raw["tag_count"]),
        positions=tuple(int(p) for p in raw["positions"]),
    )


# ---------------------------------------------------------------------------
# SSRF guard adapter
# ---------------------------------------------------------------------------


class RustSsrfGuardAdapter:
    """Drop-in for ``tessera.ssrf_guard.SSRFGuard``.

    Constructor accepts the Python signature
    ``(blocked_hostnames=None, allowlist_hostnames=None)`` for
    compatibility, but the current Rust binding only ships with
    default rules (RFC 1918, cloud metadata, file:// scheme). When a
    caller supplies custom hostnames the adapter logs a warning and
    falls back to the Python implementation for that instance.
    """

    def __init__(
        self,
        blocked_hostnames: Iterable[str] | None = None,
        allowlist_hostnames: Iterable[str] | None = None,
    ) -> None:
        rs = require_tessera_rs()
        self._fallback: Any | None = None
        if blocked_hostnames or allowlist_hostnames:
            from tessera.ssrf_guard import SSRFGuard as PySSRFGuard

            self._fallback = PySSRFGuard(
                blocked_hostnames=list(blocked_hostnames or []),
                allowlist_hostnames=list(allowlist_hostnames or []),
            )
            logger.info(
                "RustSsrfGuardAdapter: custom hostname lists are not yet "
                "supported by tessera_rs; falling back to Python SSRFGuard"
            )
            self._inner = None
        else:
            self._inner = rs.ssrf.SsrfGuard()

    def check_url(self, url: str) -> dict[str, Any]:
        if self._fallback is not None:
            return self._fallback.check_url(url)
        return dict(self._inner.check_url(url))


# ---------------------------------------------------------------------------
# URL rules adapter
# ---------------------------------------------------------------------------


class RustUrlRulesEngineAdapter:
    """Drop-in for ``tessera.url_rules.URLRulesEngine``.

    Translates the Python ``URLRule`` list into ``add_prefix`` calls
    on the Rust engine. Rules with non-prefix patterns
    (``exact``/``glob``) are not yet supported by the Rust binding;
    the adapter logs a warning and falls back to Python for the
    whole rule set in that case.
    """

    def __init__(self, rules: Sequence[Any] | None = None) -> None:
        rs = require_tessera_rs()
        self._fallback: Any | None = None
        unsupported = [
            getattr(r, "kind", None)
            for r in (rules or [])
            if getattr(r, "kind", None)
            and str(getattr(r, "kind", "")).lower() != "prefix"
        ]
        if unsupported:
            from tessera.url_rules import URLRulesEngine as PyURLRulesEngine

            self._fallback = PyURLRulesEngine(rules)
            logger.info(
                "RustUrlRulesEngineAdapter: rule kinds %s are not yet "
                "supported by tessera_rs; falling back to Python "
                "URLRulesEngine for this rule set",
                set(unsupported),
            )
            self._inner = None
            return
        self._inner = rs.url_rules.UrlRulesEngine()
        for r in rules or []:
            name = getattr(r, "rule_id", None) or getattr(r, "name", "rule")
            prefix = getattr(r, "pattern", None) or getattr(r, "prefix", "")
            action = str(getattr(r, "action", "allow")).lower()
            self._inner.add_prefix(name, prefix, action)

    def evaluate(self, url: str, method: str = "GET") -> dict[str, Any]:
        if self._fallback is not None:
            return self._fallback.evaluate(url, method)
        return dict(self._inner.evaluate(url, method))


# ---------------------------------------------------------------------------
# CEL engine adapter
# ---------------------------------------------------------------------------


class RustCelPolicyEngineAdapter:
    """Drop-in for ``tessera.cel_engine.CELPolicyEngine``."""

    def __init__(self, rules: Sequence[Any]) -> None:
        rs = require_tessera_rs()
        rust_rules = [
            rs.cel.CelRule(
                name=getattr(r, "name", "rule"),
                expression=getattr(r, "expression", ""),
                action=str(getattr(r, "action", "deny")).lower(),
                message=getattr(r, "message", ""),
            )
            for r in rules
        ]
        self._inner = rs.cel.CelPolicyEngine(rust_rules)
        # Keep the originals so AgentMesh's introspection at
        # `proxy._policy.cel_engine._rules` still works.
        self._rules = list(rules)

    @property
    def rules(self) -> list[Any]:
        return list(self._rules)

    def evaluate(self, context: Any) -> Any | None:
        """Mirror Python ``CELPolicyEngine.evaluate(CELContext)``.

        ``context`` is a ``tessera.cel_engine.CELContext``-shaped
        object. Returns a Python-shaped ``CELDecision`` namedtuple-
        style mapping, or ``None`` when no rule fires.
        """
        result = self._inner.evaluate(
            tool=str(getattr(context, "tool", "")),
            principal=str(getattr(context, "principal", "")),
            min_trust=int(getattr(context, "min_trust", 0)),
            segment_count=int(getattr(context, "segment_count", 0)),
            args={
                str(k): str(v)
                for k, v in (getattr(context, "args", {}) or {}).items()
            },
            delegation_subject=getattr(context, "delegation_subject", None),
            delegation_actions=list(
                getattr(context, "delegation_actions", ()) or ()
            ),
        )
        if result is None:
            return None
        from tessera.cel_engine import CELDecision

        return CELDecision(
            rule_name=result["rule_name"],
            action=result["action"],
            message=result["message"],
        )


__all__ = [
    "TESSERA_RS_AVAILABLE",
    "require_tessera_rs",
    "RustContextAdapter",
    "RustPolicyAdapter",
    "RustJsonlHashchainSinkAdapter",
    "RustSsrfGuardAdapter",
    "RustUrlRulesEngineAdapter",
    "RustCelPolicyEngineAdapter",
    "rust_canonical_json",
    "rust_injection_score",
    "rust_scan_unicode_tags",
]
