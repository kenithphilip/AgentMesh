"""AgentMesh MCP proxy: production security mesh for tool calls.

Integrates Tessera's full defense stack into a single proxy service.

Tier 1 (core):
 1. SPIRE identity verification (JWT-SVID on every request)
 2. Delegation chain verification (scoped token checking)
 3. Per-session rate limiting with burst detection
 4. MCP server allowlist with rug-pull detection
 5. Content scanning (heuristic, directive, schema, LLM guardrail)
 6. Policy evaluation (taint tracking + attribute-based)
 7. Compliance events with NIST/CWE enrichment
 8. Human approval gates for high-risk tool calls
 9. Read-only argument validation (path traversal, mutation guard)

Tier 2 (production hardening):
10. Value-level taint (DependencyAccumulator per-argument provenance)
11. Content inspector for binary content (PDFs, images, audio)
12. Prompt screening before context entry (delegated injection defense)
13. Secret redaction in tool outputs
14. PII scanning (optional, requires presidio)

Tier 3 (defense-in-depth):
15. Trust decay (time-based + anomaly-driven trust degradation)
16. Risk forecasting (salami detection, drift, commitment creep)
17. Plan verification (tool sequence vs user intent)
18. Side-channel mitigations (loop guard, structured results)
19. Canary tokens (output manipulation confirmation)
20. Output provenance verification (n-gram echo, task relevance)
21. CEL deny rules (expression-based policy extension)
22. xDS policy distribution (REST snapshot endpoint)

Usage::

    from agentmesh.proxy import MeshProxy

    proxy = MeshProxy(
        upstream_url="http://tools-server:3000/sse",
        policy_path="policy.yaml",
    )
    proxy.run(port=9090)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from tessera.context import Context, make_segment
from tessera.labels import Origin, TrustLevel
from tessera.policy import Policy


class _EvalRequest(BaseModel):
    tool_name: str
    args: dict = {}
    user_prompt: str = ""
    session_id: str = "default"
    agent_identity: str | None = None       # JWT-SVID or SPIFFE ID
    delegation_token: str | None = None     # signed delegation token


class _ScanRequest(BaseModel):
    text: str
    tool_name: str = "unknown"
    session_id: str = "default"


class _ApprovalRequest(BaseModel):
    tool_name: str
    args: dict = {}
    session_id: str = "default"
    approver: str = ""
    approved: bool = False


class _CheckServerRequest(BaseModel):
    server_uri: str


class _CheckOutputRequest(BaseModel):
    response: str
    user_task: str = ""


class _RAGScanRequest(BaseModel):
    text: str
    source_id: str = "unknown"
    user_prompt: str | None = None


class _MCPBaselineRequest(BaseModel):
    tools: list[dict] = []
    server_name: str = "default"


class _ToolShadowRequest(BaseModel):
    server_tools: dict[str, list[str]] = {}


class _HeartbeatRequest(BaseModel):
    agent_id: str


class _ClassifyRequest(BaseModel):
    content: str
    trajectory_id: str | None = None


class _SSRFCheckRequest(BaseModel):
    url: str


class _URLRulesCheckRequest(BaseModel):
    url: str
    method: str = "GET"


class _PolicyBuilderRequest(BaseModel):
    min_label_signal: int = 3


class _PolicyBuilderLLMRequest(BaseModel):
    """Score=True replays each LLM proposal against history (one extra
    call per proposal). Set False for fast preview without scoring."""
    score: bool = True


class _LabelRequest(BaseModel):
    seq: int
    hash: str
    label: str  # "correct" | "incorrect" | "unreviewed"


class _ReplayRequest(BaseModel):
    kinds: list[str] | None = None
    trajectory_id: str | None = None
    since: str | None = None  # ISO-8601
    until: str | None = None  # ISO-8601
    candidate: str = "current_policy"


@dataclass
class _PerSessionState:
    """Per-session resources that wrap or accompany a session's Context.

    Created lazily by ``MeshProxy._get_session_state`` and dropped via the
    SessionContextStore eviction callback so memory tracks the active
    session set. ``risk_forecaster`` and ``canary_tracker`` are optional;
    they are populated only when the corresponding feature flag is on.
    """

    accumulator: Any
    risk_forecaster: Any | None = None
    canary_tracker: Any | None = None


@dataclass
class MeshProxy:
    """AgentMesh MCP proxy with full enterprise defense stack.

    Args:
        upstream_url: SSE endpoint of the upstream MCP server.
        policy_path: Path to YAML policy file.
        signing_key: HMAC key for trust label signing.
        principal: SPIFFE ID or principal name.
        guardrail_provider: "anthropic" or "openai" (optional).
        guardrail_model: Model name for the LLM guardrail (optional).
        injection_threshold: Heuristic score threshold for taint.
        require_identity: If True, reject requests without valid identity.
        mcp_allowlist_patterns: Allowed MCP server URI patterns.
        rate_limit_calls: Max tool calls per session per window.
        rate_limit_burst: Max calls in 5-second burst window.
    """

    upstream_url: str = "http://localhost:3000"
    policy_path: str | None = None
    signing_key: bytes = b"agentmesh-default-key"
    principal: str = "agentmesh-proxy"
    guardrail_provider: str | None = None
    guardrail_model: str | None = None
    injection_threshold: float = 0.75
    # When True (default), the guardrail judge sees the post-redaction
    # form of the tool output (secrets and PII replaced with placeholders).
    # Set False to send the raw, pre-redaction text to the judge. The
    # raw form gives the judge more signal but ships secrets to the
    # provider; only opt out when the operator trusts the judge endpoint
    # at the same level as the application LLM. The choice is recorded
    # in each guardrail event detail under ``redacted_input``.
    guardrail_redact_before_judge: bool = True
    require_identity: bool = False
    mcp_allowlist_patterns: list[str] = field(default_factory=list)
    rate_limit_calls: int = 50
    rate_limit_burst: int = 10

    # Tier 2: production hardening
    enable_prompt_screening: bool = True
    enable_secret_redaction: bool = True
    enable_pii_scanning: bool = False       # requires presidio

    # Tier 3: defense-in-depth
    enable_trust_decay: bool = False
    enable_risk_forecasting: bool = True
    enable_plan_verification: bool = True
    enable_canary_tokens: bool = False
    cel_rules_path: str | None = None

    # Persistent hash-chained audit log (JSONL). Opt-in via path.
    # When seal_key is set, a companion .seal file is written with an
    # HMAC over (seq, last_hash) so truncation is detectable.
    audit_log_path: str | None = None
    audit_log_seal_key: bytes | None = None
    audit_log_fsync_every: int = 1

    # Ground-truth labels for replay scoring. Persisted as JSON.
    # Defaults to ``<audit_log_path>.labels.json`` when audit log is on.
    audit_label_path: str | None = None

    # Multi-tenant session state. Each session_id gets its own Context,
    # DependencyAccumulator, risk forecaster, and canary tracker. Sessions
    # expire after ``session_context_ttl_seconds`` of inactivity; the LRU
    # session is evicted when active sessions exceed ``session_context_max``.
    # Defaults give a one-hour lifetime and a 10,000-session cap; tighten
    # both for high-fanout deployments.
    session_context_ttl_seconds: float = 3600.0
    session_context_max: int = 10000

    # Tier A+B: identity, transport, exports
    trust_domain: str = "agentmesh.local"
    spire_socket: str | None = None
    approval_webhook_url: str | None = None
    enable_rag_guard: bool = False
    enable_sarif: bool = True
    enable_telemetry: bool = False
    enable_xds_server: bool = False

    # Sensitivity labels and information flow control
    # Trajectory-keyed high-water-mark model. Pass an outbound_tool_registry
    # mapping tool_name -> (outbound, max_sensitivity) to enforce IFC.
    # When enabled without a registry, unknown tools default to inbound/local.
    enable_sensitivity_labeling: bool = False
    outbound_tool_registry: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Destructive operation guard (explicit pattern deny-list).
    # Every pattern is a hard deny with a stable rule_id in the audit log.
    # To tighten or loosen, pass a custom DestructiveGuard via the
    # destructive_guard_override field.
    enable_destructive_guard: bool = True

    # Supply chain attack scanner (package install commands, manifests).
    # Uses the Scanner protocol from tessera.scanners. Severity threshold
    # follows the scanner's own default ("high") unless overridden in the
    # SupplyChainScanner constructor by a downstream composer.
    enable_supply_chain_scanner: bool = True

    # SSRF guard. Blocks outbound URLs that resolve to RFC1918,
    # loopback, link-local, cloud metadata, or non-http(s) schemes.
    # Optional allowlist mode tightens to deny-by-default.
    enable_ssrf_guard: bool = True
    ssrf_blocked_hostnames: list[str] = field(default_factory=list)
    ssrf_allowlist_hostnames: list[str] | None = None

    # Static URL pattern rules. A fast deterministic gate that runs
    # before scanners and the SSRF guard. Hits short-circuit the rest
    # of the pipeline; misses fall through to the full evaluator.
    # Each rule is a dict with keys:
    #   rule_id, pattern, kind ("exact" | "prefix" | "glob"),
    #   action ("allow" | "deny"), methods (optional list), description
    enable_url_rules: bool = True
    url_rules: list[dict[str, Any]] = field(default_factory=list)

    # Tier 4: optional Rust fast-path. When True AND `tessera-rs`
    # (>=0.10.0a1) is importable, swap a curated subset of hot-path
    # primitives to the Rust implementations: Policy.evaluate +
    # Context.add_segment, the JSONL hash-chained audit sink, the
    # heuristic + unicode scanners, the SSRF guard, the URL rules
    # engine, and the CEL deny-rule evaluator. Default False so
    # existing deployments are not affected. See
    # docs/RUST_PRIMITIVES.md for the full unsupported-surface list.
    use_rust_primitives: bool = False

    # Internal state (not constructor args)
    _policy: Policy | None = field(default=None, init=False, repr=False)
    # Per-session state lives here. _contexts is the canonical session
    # store (TTL + LRU eviction); _session_states holds the adjacent
    # accumulator / forecaster / canary tracker keyed on the same
    # session_ids, cleaned up via the eviction callback.
    _contexts: Any = field(default=None, init=False, repr=False)
    _session_states: dict = field(default_factory=dict, init=False, repr=False)
    _guardrail: Any = field(default=None, init=False, repr=False)
    _rate_limiter: Any = field(default=None, init=False, repr=False)
    _mcp_allowlist: Any = field(default=None, init=False, repr=False)
    _audit_log: Any = field(default=None, init=False, repr=False)
    _definition_tracker: Any = field(default=None, init=False, repr=False)
    _secret_registry: Any = field(default=None, init=False, repr=False)
    _trust_decay_policy: Any = field(default=None, init=False, repr=False)
    _loop_guard: Any = field(default=None, init=False, repr=False)
    _pii_scanner: Any = field(default=None, init=False, repr=False)
    _identity: Any = field(default=None, init=False, repr=False)
    _transport: Any = field(default=None, init=False, repr=False)
    _exports: Any = field(default=None, init=False, repr=False)
    _invariant_checker: Any = field(default=None, init=False, repr=False)
    _session_store: Any = field(default=None, init=False, repr=False)
    _evidence_buffer: Any = field(default=None, init=False, repr=False)
    _cooldown: Any = field(default=None, init=False, repr=False)
    _classifier: Any = field(default=None, init=False, repr=False)
    _hwm: Any = field(default=None, init=False, repr=False)
    _outbound_policy: Any = field(default=None, init=False, repr=False)
    _destructive_guard: Any = field(default=None, init=False, repr=False)
    _supply_chain_scanner: Any = field(default=None, init=False, repr=False)
    _yara_scanner: Any = field(default=None, init=False, repr=False)
    _ssrf_guard: Any = field(default=None, init=False, repr=False)
    _url_rules: Any = field(default=None, init=False, repr=False)
    _audit_sink: Any = field(default=None, init=False, repr=False)
    _label_store: Any = field(default=None, init=False, repr=False)

    def _rust_primitives_active(self, surface: str) -> bool:
        """Decide whether to swap a given surface to the Rust adapter.

        Returns True when:
        1. ``self.use_rust_primitives`` is True
        2. ``tessera-rs`` (>=0.10.0) is importable
        3. ``surface`` is in the curated swap list

        Logs once at INFO when the swap activates so operators can
        see what is running on Rust.
        """
        if not self.use_rust_primitives:
            return False
        try:
            from agentmesh.adapters.tessera_rs import TESSERA_RS_AVAILABLE
        except ImportError:
            return False
        if not TESSERA_RS_AVAILABLE:
            import logging
            logging.getLogger(__name__).warning(
                "use_rust_primitives=True but tessera-rs is not installed; "
                "falling back to Python primitives. Install with: pip install tessera-rs"
            )
            self.use_rust_primitives = False  # one-shot warning
            return False
        # Surfaces currently shipped with adapters. Extend as more
        # adapters land in agentmesh.adapters.tessera_rs. Each surface
        # name maps to one or more swap sites in __post_init__.
        return surface in {
            "audit",
            "ratelimit",
            "ssrf",
            "url_rules",
            "policy",
            "context",
            "cel",
            "scanners",
        }

    def __post_init__(self) -> None:
        # 1. Load policy from YAML
        if self.policy_path and os.path.exists(self.policy_path):
            from tessera.ir import compile_policy, from_yaml_path
            self._policy = compile_policy(from_yaml_path(self.policy_path))
        else:
            self._policy = Policy()

        if self.use_rust_primitives:
            import logging
            log = logging.getLogger(__name__)
            from agentmesh.adapters.tessera_rs import TESSERA_RS_AVAILABLE
            if TESSERA_RS_AVAILABLE:
                log.info(
                    "use_rust_primitives=True: tessera-rs adapters available "
                    "for audit, ratelimit, ssrf, url_rules, scanners, cel, "
                    "policy, context. Auto-swapped on this proxy: audit, "
                    "ratelimit, ssrf, url_rules. See docs/RUST_PRIMITIVES.md "
                    "for the full surface map and how to wire policy / "
                    "context / cel / scanners into your code path."
                )
            else:
                log.warning(
                    "use_rust_primitives=True but tessera-rs is not installed; "
                    "falling back to Python primitives. Install with: pip install tessera-rs"
                )
                self.use_rust_primitives = False

        # 2. Initialize LLM guardrail (optional)
        if self.guardrail_provider and self.guardrail_model:
            try:
                from tessera.guardrail import GuardrailCache, LLMGuardrail
                if self.guardrail_provider == "anthropic":
                    import anthropic
                    client = anthropic.Anthropic()
                elif self.guardrail_provider == "openai":
                    from openai import OpenAI
                    client = OpenAI()
                else:
                    client = None
                if client:
                    self._guardrail = LLMGuardrail(
                        client=client, model=self.guardrail_model,
                        cache=GuardrailCache(),
                    )
            except ImportError:
                pass

        # 3. Initialize rate limiter
        from datetime import timedelta
        if self._rust_primitives_active("ratelimit"):
            from agentmesh.adapters.tessera_rs import RustToolCallRateLimitAdapter
            self._rate_limiter = RustToolCallRateLimitAdapter(
                max_calls=self.rate_limit_calls,
                burst_threshold=self.rate_limit_burst,
                burst_window=timedelta(seconds=5),
                cooldown=timedelta(seconds=30),
                session_lifetime_max=500,
            )
        else:
            from tessera.ratelimit import ToolCallRateLimit
            self._rate_limiter = ToolCallRateLimit(
                max_calls=self.rate_limit_calls,
                burst_threshold=self.rate_limit_burst,
                burst_window=timedelta(seconds=5),
                cooldown=timedelta(seconds=30),
                session_lifetime_max=500,
            )

        # 4. Initialize MCP server allowlist
        if self.mcp_allowlist_patterns:
            from tessera.mcp_allowlist import MCPServerAllowlist
            self._mcp_allowlist = MCPServerAllowlist(self.mcp_allowlist_patterns)

        # 5. Initialize compliance audit log
        from tessera.compliance import ChainedAuditLog
        from tessera.events import register_sink
        self._audit_log = ChainedAuditLog()
        register_sink(self._audit_log)

        # 5b. Persistent hash-chained audit log (opt-in via audit_log_path).
        # This is the durable record for replay and forensic verification.
        # The in-memory ChainedAuditLog above is kept for backward-compat
        # callers that query the chain via self.audit_chain_valid.
        if self.audit_log_path:
            if self._rust_primitives_active("audit"):
                from agentmesh.adapters.tessera_rs import (
                    RustJsonlHashchainSinkAdapter,
                )
                self._audit_sink = RustJsonlHashchainSinkAdapter(
                    self.audit_log_path,
                    fsync_every=self.audit_log_fsync_every,
                    seal_key=self.audit_log_seal_key,
                )
            else:
                from tessera.audit_log import JSONLHashchainSink
                self._audit_sink = JSONLHashchainSink(
                    self.audit_log_path,
                    fsync_every=self.audit_log_fsync_every,
                    seal_key=self.audit_log_seal_key,
                )
            register_sink(self._audit_sink)

        # 5c. Replay label store. Author-time ground-truth annotations
        # live alongside the audit log but are mutable by design. When
        # audit_label_path is set (or defaulted from audit_log_path),
        # labels persist across restarts so replay scoring is stable.
        from tessera.replay import LabelStore
        label_path = self.audit_label_path
        if label_path is None and self.audit_log_path:
            label_path = f"{self.audit_log_path}.labels.json"
        if label_path is not None:
            self._label_store = LabelStore.load(label_path)
            self.audit_label_path = label_path
        else:
            self._label_store = LabelStore()

        # 6. Initialize tool definition tracker (rug-pull detection)
        from tessera.mcp_allowlist import ToolDefinitionTracker
        self._definition_tracker = ToolDefinitionTracker()

        # 7. Per-session Context store (SessionContextStore). Every
        # taint-tracking decision runs against a session-scoped Context,
        # so user A's web-tainted segments cannot deny user B's tool
        # calls. Accumulator, forecaster, and canary tracker are
        # session-scoped too and live in ``_session_states``, cleaned
        # up by the eviction callback in lockstep with their Context.
        from tessera.session_context import SessionContextStore
        self._contexts = SessionContextStore(
            ttl_seconds=self.session_context_ttl_seconds,
            max_sessions=self.session_context_max,
            on_evict=self._on_session_evicted,
        )

        # 8. Secret registry for redaction
        if self.enable_secret_redaction:
            from tessera.redaction import SecretRegistry
            self._secret_registry = SecretRegistry()

        # 11. PII scanner
        if self.enable_pii_scanning:
            from tessera.scanners.pii import PIIScanner
            self._pii_scanner = PIIScanner()

        # 12. Trust decay
        if self.enable_trust_decay:
            from tessera.trust_decay import TrustDecayPolicy
            self._trust_decay_policy = TrustDecayPolicy()

        # 12. Side-channel mitigation: loop guard
        from tessera.side_channels import LoopGuard
        self._loop_guard = LoopGuard(max_iterations=200)

        # 13. CEL deny rules (loaded through policy IR if cel_rules_path set)
        if self.cel_rules_path and os.path.exists(self.cel_rules_path):
            try:
                from tessera.cel_engine import CELPolicyEngine, CELRule
                import yaml
                with open(self.cel_rules_path) as f:
                    cel_data = yaml.safe_load(f) or {}
                rules = [
                    CELRule(name=r.get("name", f"rule_{i}"), expression=r["expression"])
                    for i, r in enumerate(cel_data.get("rules", []))
                ]
                if rules:
                    self._policy.cel_engine = CELPolicyEngine(rules)
            except (ImportError, Exception):
                pass

        # -- Tier A+B helpers --

        # 14. Identity provider (signing, SPIRE, mTLS, liveness)
        from agentmesh.identity import IdentityProvider
        self._identity = IdentityProvider(
            signing_key=self.signing_key,
            principal=self.principal,
            trust_domain=self.trust_domain,
            spire_socket=self.spire_socket,
        )

        # 15. MCP transport (baseline drift, RAG guard)
        if self.enable_rag_guard:
            from agentmesh.transport import MCPTransport
            self._transport = MCPTransport(
                upstream_url=self.upstream_url,
                principal=self.principal,
                signing_key=self.signing_key,
            )

        # 16. Compliance exports (SARIF, telemetry, xDS, confidence)
        from agentmesh.exports import ComplianceExporter
        self._exports = ComplianceExporter(
            signing_key=self.signing_key,
            principal=self.principal,
            enable_sarif=self.enable_sarif,
            enable_telemetry=self.enable_telemetry,
            enable_xds_server=self.enable_xds_server,
        )

        # 17. Policy invariant checker (control-flow enforcement)
        from tessera.policy_invariant import PolicyInvariantChecker
        self._invariant_checker = PolicyInvariantChecker()

        # 18. Session store for structured approval workflows
        from tessera.sessions import SessionStore
        self._session_store = SessionStore(encryption_key=self.signing_key[:32] if len(self.signing_key) >= 32 else None)

        # 19. Evidence buffer for forensic bundles
        from tessera.events import register_sink
        from tessera.evidence import EvidenceBuffer
        self._evidence_buffer = EvidenceBuffer()
        register_sink(self._evidence_buffer)

        # 20. Cooldown escalator (adaptive denial response)
        from tessera.risk.cooldown import CooldownEscalator
        self._cooldown = CooldownEscalator()

        # 21. Sensitivity + IFC: classifier, high-water mark, outbound policy.
        # These are independent of enable_sensitivity_labeling; the flag only
        # controls auto-classification in scan_and_label. The /v1/sensitivity
        # endpoints always work.
        from tessera.sensitivity import (
            HighWaterMark,
            OutboundPolicy,
            SensitivityClassifier,
            SensitivityLabel,
            ToolClassification,
        )
        self._classifier = SensitivityClassifier()
        self._hwm = HighWaterMark()

        # Build OutboundPolicy registry from config dict.
        # Expected shape: {"tool_name": {"outbound": bool, "max_sensitivity": "INTERNAL"}}
        registry = {}
        for tool, cfg in self.outbound_tool_registry.items():
            registry[tool] = ToolClassification(
                outbound=bool(cfg.get("outbound", False)),
                max_sensitivity=SensitivityLabel.from_str(
                    cfg.get("max_sensitivity", "INTERNAL")
                ),
            )
        self._outbound_policy = OutboundPolicy(registry=registry)

        # 22. Destructive guard (always instantiated; gated by flag at call site)
        from tessera.destructive_guard import DestructiveGuard
        self._destructive_guard = DestructiveGuard()

        # 23. Supply chain scanner (always instantiated; gated by flag)
        from tessera.scanners.supply_chain import SupplyChainScanner
        self._supply_chain_scanner = SupplyChainScanner()

        # 24. YARA scanner (lazy import; available=False if yara-x not installed)
        from tessera.scanners.yara import YaraScanner
        self._yara_scanner = YaraScanner()

        # 25. SSRF guard. Always instantiated; gated by flag at the call
        # site. Uses the default socket-based resolver so hostnames are
        # resolved before the CIDR check, which is the only way to catch
        # DNS-rebinding-style payloads.
        if self._rust_primitives_active("ssrf"):
            from agentmesh.adapters.tessera_rs import RustSsrfGuardAdapter
            self._ssrf_guard = RustSsrfGuardAdapter(
                blocked_hostnames=self.ssrf_blocked_hostnames,
                allowlist_hostnames=self.ssrf_allowlist_hostnames,
            )
        else:
            from tessera.ssrf_guard import SSRFGuard
            self._ssrf_guard = SSRFGuard(
                blocked_hostnames=self.ssrf_blocked_hostnames,
                allowlist_hostnames=self.ssrf_allowlist_hostnames,
            )

        # 26. Static URL rules engine. Always instantiated so the
        # endpoint is callable; only consulted in evaluate_tool_call
        # when enable_url_rules is True and rules are non-empty.
        from tessera.url_rules import (
            PatternKind,
            RuleAction,
            URLRule,
            URLRulesEngine,
        )
        rules = []
        for spec in self.url_rules:
            try:
                rules.append(URLRule(
                    rule_id=str(spec["rule_id"]),
                    pattern=str(spec["pattern"]),
                    kind=PatternKind(spec.get("kind", "exact")),
                    action=RuleAction(spec.get("action", "allow")),
                    methods=(
                        tuple(m.upper() for m in spec["methods"])
                        if spec.get("methods") is not None else None
                    ),
                    description=str(spec.get("description", "")),
                ))
            except (KeyError, ValueError):
                # Skip malformed rule specs; the analyzer-style endpoint
                # would surface these. The proxy itself fails open on
                # config rather than failing to start.
                continue
        self._url_rules = URLRulesEngine(rules)

    # ------------------------------------------------------------------
    # Per-session state helpers
    # ------------------------------------------------------------------

    def _get_session_state(self, session_id: str = "default") -> _PerSessionState:
        """Return per-session accumulator / forecaster / canary tracker.

        Created lazily on first access. The corresponding Context is
        ensured first via :meth:`_contexts.get` so the accumulator's
        underlying Context is the same object the proxy will read and
        write through ``self._contexts.get(session_id)`` everywhere
        else. Cleared by :meth:`_on_session_evicted` when the
        SessionContextStore drops the session.
        """
        state = self._session_states.get(session_id)
        if state is not None:
            return state
        from tessera.taint import DependencyAccumulator
        ctx = self._contexts.get(session_id)
        state = _PerSessionState(
            accumulator=DependencyAccumulator(context=ctx),
        )
        if self.enable_risk_forecasting:
            from tessera.risk.forecaster import SessionRiskForecaster
            state.risk_forecaster = SessionRiskForecaster()
        if self.enable_canary_tokens:
            from tessera.scanners.canary import SegmentCanaryTracker
            state.canary_tracker = SegmentCanaryTracker()
        self._session_states[session_id] = state
        return state

    def _on_session_evicted(self, session_id: str) -> None:
        """SessionContextStore eviction callback.

        Drops the per-session adjacent state so memory tracks the active
        session set. Idempotent (the dict pop handles the missing case).
        """
        self._session_states.pop(session_id, None)

    # ------------------------------------------------------------------
    # Core evaluation pipeline
    # ------------------------------------------------------------------

    def evaluate_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        session_id: str = "default",
        agent_identity: str | None = None,
        delegation_token_str: str | None = None,
    ) -> tuple[bool, str]:
        """Full evaluation pipeline for a tool call.

        Runs all six enterprise checks in order:
        1. Identity verification
        2. Rate limiting
        3. Delegation token verification
        4. Policy evaluation (taint tracking)
        5. Read-only argument validation
        6. Human approval check

        Returns (allowed, reason).
        """
        # 0. Policy invariant: mark that we received output
        self._invariant_checker.on_output_received(session_id)

        # 1. Identity verification (with SPIRE/JWT when available)
        if self.require_identity and not agent_identity:
            return False, "identity required: no agent_identity provided"
        if agent_identity and self._identity is not None:
            self._identity.heartbeat(agent_identity)

        # 2. Rate limiting
        allowed, reason = self._rate_limiter.check(session_id, tool_name)
        if not allowed:
            return False, f"rate limit: {reason}"

        # 2b. Destructive operation guard. Runs first so audit logs show
        # the explicit pattern_id rather than a scanner threshold.
        if self.enable_destructive_guard and args:
            dguard_result = self._destructive_guard.check(tool_name, args)
            if not dguard_result.allowed:
                from tessera.events import EventKind, SecurityEvent, emit
                top_match = dguard_result.matches[0]
                emit(SecurityEvent.now(
                    kind=EventKind.POLICY_DENY,
                    principal=agent_identity or self.principal,
                    detail={
                        "check": "destructive_guard",
                        "tool": tool_name,
                        "pattern_id": top_match.pattern_id,
                        "category": top_match.category,
                        "description": top_match.description,
                        "arg_path": top_match.arg_path,
                        "matched_text": top_match.matched_text[:120],
                    },
                ))
                return False, dguard_result.primary_reason

        # 2c. Supply chain attack scanner (Scanner protocol)
        if self.enable_supply_chain_scanner and args:
            sc_result = self._supply_chain_scanner.scan(
                tool_name=tool_name, args=args, trajectory_id=session_id,
            )
            if not sc_result.allowed:
                from tessera.events import EventKind, SecurityEvent, emit
                top = sc_result.findings[0]
                emit(SecurityEvent.now(
                    kind=EventKind.POLICY_DENY,
                    principal=agent_identity or self.principal,
                    detail={
                        "check": "supply_chain",
                        "tool": tool_name,
                        "rule_id": top.rule_id,
                        "severity": top.severity,
                        "message": top.message,
                        "arg_path": top.arg_path,
                        "evidence": top.evidence[:120],
                        "metadata": top.metadata,
                    },
                ))
                return False, sc_result.primary_reason

        # 2c-1. Static URL rules. Fast deterministic gate before the
        # SSRF guard and scanners. Hits short-circuit (deny halts the
        # call; allow signals "this URL is pre-vetted, skip nothing
        # but still let scanners check non-URL args"). NO_MATCH falls
        # through to the rest of the pipeline.
        if (
            self.enable_url_rules
            and self._url_rules is not None
            and self._url_rules.rule_count > 0
            and args
        ):
            from tessera.ssrf_guard import _flatten_args, _URL_RE
            method = (
                str(args.get("method", "GET")).upper()
                if isinstance(args, dict) else "GET"
            )
            for path, text in _flatten_args(args):
                for match in _URL_RE.finditer(text):
                    url = match.group(0)
                    decision = self._url_rules.evaluate(url, method=method)
                    if decision.verdict.value == "deny":
                        from tessera.events import (
                            EventKind, SecurityEvent, emit,
                        )
                        emit(SecurityEvent.now(
                            kind=EventKind.POLICY_DENY,
                            principal=agent_identity or self.principal,
                            detail={
                                "check": "url_rules",
                                "tool": tool_name,
                                "rule_id": decision.rule_id,
                                "description": decision.description,
                                "url": decision.url,
                                "method": decision.method,
                                "arg_path": path,
                            },
                        ))
                        return False, (
                            f"{decision.rule_id}: {decision.description}"
                            if decision.description
                            else f"url_rules: {decision.rule_id}"
                        )

        # 2c-2. SSRF guard. Walks args for URL-shaped strings, resolves
        # hostnames, denies if anything resolves to private space, cloud
        # metadata, or non-http(s) schemes. Cheap when no URLs appear in
        # args (regex pre-filter); pays DNS only when one does.
        if self.enable_ssrf_guard and args:
            ssrf_result = self._ssrf_guard.scan(
                tool_name=tool_name, args=args, trajectory_id=session_id,
            )
            if not ssrf_result.allowed:
                from tessera.events import EventKind, SecurityEvent, emit
                top = ssrf_result.findings[0]
                emit(SecurityEvent.now(
                    kind=EventKind.POLICY_DENY,
                    principal=agent_identity or self.principal,
                    detail={
                        "check": "ssrf_guard",
                        "tool": tool_name,
                        "rule_id": top.rule_id,
                        "severity": top.severity,
                        "message": top.message,
                        "arg_path": top.arg_path,
                        "evidence": top.evidence[:200],
                        "metadata": top.metadata,
                    },
                ))
                return False, ssrf_result.primary_reason

        # 2d. YARA scanner (no-op when yara-x not installed or no rules loaded)
        if self._yara_scanner is not None and self._yara_scanner.available and args:
            yara_result = self._yara_scanner.scan(
                tool_name=tool_name, args=args, trajectory_id=session_id,
            )
            if not yara_result.allowed:
                from tessera.events import EventKind, SecurityEvent, emit
                top = yara_result.findings[0]
                emit(SecurityEvent.now(
                    kind=EventKind.POLICY_DENY,
                    principal=agent_identity or self.principal,
                    detail={
                        "check": "yara",
                        "tool": tool_name,
                        "rule_id": top.rule_id,
                        "severity": top.severity,
                        "message": top.message,
                        "arg_path": top.arg_path,
                    },
                ))
                return False, yara_result.primary_reason

        # 3. Delegation token verification (if provided)
        delegation = None
        if delegation_token_str:
            try:
                from tessera.delegation import DelegationToken, verify_delegation
                import json
                token_data = json.loads(delegation_token_str)
                delegation = DelegationToken(**token_data)
                if not verify_delegation(delegation, self.signing_key):
                    return False, "delegation: invalid token signature"
            except Exception as e:
                return False, f"delegation: {str(e)[:100]}"

        # 4. Policy evaluation (taint tracking, with optional trust decay)
        # Per-session: every other session's segments are invisible here.
        session_ctx = self._contexts.get(session_id)
        eval_context = session_ctx
        if self._trust_decay_policy is not None:
            from tessera.trust_decay import DecayAwareContext
            eval_context = DecayAwareContext(
                session_ctx, policy=self._trust_decay_policy,
            )

        decision = self._policy.evaluate(
            eval_context, tool_name, args=args,
            delegation=delegation,
            expected_delegate=agent_identity,
        )

        if not decision.allowed:
            # 5. Compliance event enrichment
            from tessera.compliance import enrich_event
            from tessera.events import EventKind, SecurityEvent, emit
            event = SecurityEvent.now(
                kind=EventKind.POLICY_DENY,
                principal=agent_identity or self.principal,
                detail={
                    "tool": tool_name,
                    "session_id": session_id,
                    "required_trust": int(decision.required_trust),
                    "observed_trust": int(decision.observed_trust),
                    "reason": decision.reason,
                },
            )
            emit(event)
            return False, decision.reason or "policy denied"

        # 5b. Policy invariant: mark evaluation happened
        self._invariant_checker.on_policy_evaluated(session_id)

        # 6. Human approval check (with session store and cooldown)
        if tool_name in self._policy._human_approval_tools:
            escalation = self._cooldown.state()
            if escalation.level >= 2:
                return False, "cooldown: escalation level 2, all side-effecting tools blocked"
            return False, f"human approval required for tool {tool_name!r}"

        # 7. Read-only argument validation
        from fnmatch import fnmatch
        is_read_only = False
        for key, req in self._policy.requirements.items():
            name, _ = key
            if fnmatch(tool_name, name) and not req.side_effects:
                is_read_only = True
                break

        if is_read_only and args:
            from tessera.read_only_guard import check_read_only_args
            guard_result = check_read_only_args(tool_name, args)
            if not guard_result.passed:
                violations = "; ".join(v[1] for v in guard_result.violations)
                return False, f"read-only guard: {violations}"

        # 8. Value-level taint (per-argument provenance, session-scoped)
        sess_state = self._get_session_state(session_id)
        if args and sess_state.accumulator is not None:
            for arg_name, arg_val in args.items():
                if isinstance(arg_val, str) and len(arg_val) >= 3:
                    sess_state.accumulator.bind_from_tool_output(
                        arg_name, arg_val, tool_name,
                    )

        # 9. Plan verification (tool sequence vs user intent)
        if self.enable_plan_verification and session_ctx.segments:
            from tessera.plan_verifier import infer_spec_from_prompt, verify_sequence
            user_segs = [
                s for s in session_ctx.segments
                if s.label.trust_level >= TrustLevel.USER
            ]
            if user_segs:
                spec = infer_spec_from_prompt(user_segs[0].content)
                result = verify_sequence(spec, [tool_name])
                if not result.passed and result.score >= 0.5:
                    return False, f"plan verifier: {'; '.join(result.violations)}"

        # 10. Risk forecasting (salami detection, dynamic irreversibility)
        # Per-session: each tenant's salami chain is tracked separately,
        # so user A's call pattern cannot trip user B's threshold.
        if sess_state.risk_forecaster is not None:
            from tessera.risk.irreversibility import score_irreversibility
            irrev = score_irreversibility(tool_name, args)
            risk = sess_state.risk_forecaster.record(
                tool_name, args, irrev_score=irrev.final_score,
            )
            if risk.should_pause:
                return False, f"risk forecast: overall_risk={risk.overall_risk:.1f} (threshold exceeded)"

        # 11. Toxic flow check
        if args and not is_read_only:
            from tessera.read_only_guard import check_toxic_flow
            has_untrusted = any(
                s.label.trust_level < TrustLevel.USER
                for s in session_ctx.segments
            )
            has_sensitive = any(
                kw in str(args).lower()
                for kw in ("password", "api_key", "secret", "credential", "ssn")
            )
            toxic = check_toxic_flow(has_untrusted, has_sensitive, destination="external")
            if toxic.toxic:
                return False, f"toxic flow: {toxic.reason}"

        # 11b. Information flow control: OutboundPolicy is a pure read of
        # the trajectory HWM. The HWM is populated by /v1/sensitivity/classify
        # or scan_and_label. A deny here is reproducible from audit data.
        if self.enable_sensitivity_labeling and self._outbound_policy is not None:
            from tessera.events import EventKind, SecurityEvent, emit
            hwm = self._hwm.get(session_id)
            ifc_decision = self._outbound_policy.check(tool_name, hwm)
            if not ifc_decision.allowed:
                emit(SecurityEvent.now(
                    kind=EventKind.POLICY_DENY,
                    principal=agent_identity or self.principal,
                    detail={
                        "check": "ifc_outbound",
                        "tool": tool_name,
                        "hwm": ifc_decision.hwm.name,
                        "tool_max": ifc_decision.tool_max.name,
                        "reason": ifc_decision.reason,
                    },
                ))
                return False, ifc_decision.reason

        # 12. Policy invariant: assert no bypass before allowing
        try:
            self._invariant_checker.assert_before_tool(session_id, tool_name)
        except Exception:
            return False, "policy invariant: tool execution without policy evaluation"

        # Telemetry span (no-op if disabled)
        if self._exports is not None:
            self._exports.emit_decision_span(decision)

        return True, "allowed"

    def scan_and_label(
        self,
        tool_name: str,
        output_text: str,
        raw_output: Any = None,
        session_id: str = "default",
    ) -> tuple[str, TrustLevel]:
        """Scan tool output, label, and add to context.

        Args:
            tool_name: Name of the tool that produced the output.
            output_text: Text content of the tool output.
            raw_output: Optional raw output for binary content inspection.

        Returns:
            Tuple of (possibly redacted text, assigned trust level).
        """
        from tessera.scanners.directive import scan_directive
        from tessera.scanners.heuristic import injection_scores
        from tessera.scanners.tool_output_schema import (
            ToolOutputKind, _resolve_kind, scan_tool_output,
        )

        # -- Phase 0: binary content inspection (images, PDFs, audio) --
        if raw_output is not None:
            from tessera.content_inspector import inspect_content, TrustRecommendation
            inspection = inspect_content(raw_output, tool_name)
            if inspection.threats:
                from tessera.events import EventKind, SecurityEvent, emit
                emit(SecurityEvent.now(
                    kind=EventKind.CONTENT_INJECTION_DETECTED,
                    principal=self.principal,
                    detail={
                        "scanner": "content_inspector",
                        "tool_name": tool_name,
                        "content_type": inspection.content_type.value,
                        "threats": list(inspection.threats),
                    },
                ))
            if inspection.extracted_text:
                output_text = inspection.extracted_text
            if inspection.trust == TrustRecommendation.BLOCKED:
                seg = make_segment(
                    output_text or "[blocked binary content]",
                    Origin.WEB, self.principal, self.signing_key,
                    trust_level=TrustLevel.UNTRUSTED,
                )
                self._contexts.get(session_id).add(seg)
                return output_text or "[blocked binary content]", TrustLevel.UNTRUSTED

        # Snapshot the pre-redaction text. The guardrail can opt to see
        # this raw form (more signal for the judge) instead of the
        # redacted form (no secrets sent to the provider). Stored
        # locally so subsequent phases can keep mutating output_text
        # without losing the original.
        pre_redaction_text = output_text

        # -- Phase 1: secret redaction --
        if self._secret_registry is not None and len(self._secret_registry) > 0:
            from tessera.redaction import redact_nested
            output_text, redacted = redact_nested(output_text, self._secret_registry)

        # -- Phase 1a: sensitivity classification -> HWM update --
        # Runs before PII redaction so the classifier sees the raw patterns
        # (SSN, keys, etc.) that drive RESTRICTED. Auto-classification is
        # gated on enable_sensitivity_labeling so the flag has a single
        # clear meaning: "automatically observe tool outputs into the HWM".
        # Explicit classification via /v1/sensitivity/classify always works.
        if self.enable_sensitivity_labeling and self._classifier is not None:
            from tessera.events import EventKind, SecurityEvent, emit
            from tessera.sensitivity import SensitivityLabel
            classification = self._classifier.classify(output_text)
            if classification.label > SensitivityLabel.PUBLIC:
                self._hwm.observe(session_id, classification.label)
                emit(SecurityEvent.now(
                    kind=EventKind.CONTENT_INJECTION_DETECTED,
                    principal=self.principal,
                    detail={
                        "scanner": "sensitivity",
                        "tool_name": tool_name,
                        "session_id": session_id,
                        "label": classification.label.name,
                        "matched_rule_ids": list(classification.matched_rule_ids),
                    },
                ))

        # -- Phase 1b: PII scanning and redaction --
        pii_entities: list = []
        if self._pii_scanner is not None:
            pii_entities = self._pii_scanner.scan(output_text)
            if pii_entities:
                output_text = self._pii_scanner.redact(output_text)
                from tessera.events import EventKind, SecurityEvent, emit
                emit(SecurityEvent.now(
                    kind=EventKind.CONTENT_INJECTION_DETECTED,
                    principal=self.principal,
                    detail={
                        "scanner": "pii",
                        "tool_name": tool_name,
                        "entity_types": list({e.entity_type for e in pii_entities}),
                        "entity_count": len(pii_entities),
                        "owasp": "LLM02",
                    },
                ))

        # -- Phase 1c: Unicode hidden content --
        from tessera.scanners.unicode import scan_unicode_tags
        unicode_result = scan_unicode_tags(output_text)
        unicode_tainted = unicode_result.detected

        # -- Phase 2: text scanners --
        output_kind = _resolve_kind(tool_name)
        is_free_text = output_kind == ToolOutputKind.FREE_TEXT

        h_regex, h_window = injection_scores(output_text)
        d_result = scan_directive(output_text)
        s_result = scan_tool_output(tool_name, output_text)

        if is_free_text:
            override_confirmed = h_regex >= 0.9 and h_window >= 0.85
            is_tainted = d_result.detected or override_confirmed
            if not is_tainted and self._guardrail is not None:
                judge_text = (
                    output_text if self.guardrail_redact_before_judge
                    else pre_redaction_text
                )
                is_tainted = self._guardrail.should_taint(
                    judge_text,
                    tool_name,
                    redacted=self.guardrail_redact_before_judge,
                )
        else:
            regex_match = h_regex >= 0.9
            window_corroborated = (
                h_window >= self.injection_threshold
                and (d_result.score > 0.2 or s_result.score > 0.3)
            )
            is_tainted = (
                regex_match or d_result.detected
                or s_result.violation or window_corroborated
            )

        # Phase 2b: intent verification (unrequested actions)
        from tessera.scanners.intent import scan_intent
        user_segs = [
            s for s in self._contexts.get(session_id).segments
            if s.label.trust_level >= TrustLevel.USER
        ]
        user_prompt = user_segs[0].content if user_segs else None
        intent_result = scan_intent(output_text, user_prompt)
        if intent_result.suspicious:
            is_tainted = True

        # Unicode hidden content forces taint
        if unicode_tainted:
            is_tainted = True

        trust = TrustLevel.UNTRUSTED if is_tainted else TrustLevel.USER
        origin = Origin.WEB if is_tainted else Origin.TOOL

        # -- Phase 3: canary injection (before adding to context) --
        # Per-session canary tracker: tokens injected for session A
        # cannot be matched against session B's response.
        labeled_text = output_text
        sess_state = self._get_session_state(session_id)
        session_ctx = self._contexts.get(session_id)
        if sess_state.canary_tracker is not None:
            seg_id = f"seg_{len(session_ctx.segments)}"
            labeled_text, _token = sess_state.canary_tracker.inject_segment(
                seg_id, output_text,
            )
            if is_tainted:
                sess_state.canary_tracker.flag_directive(seg_id)

        seg = make_segment(
            labeled_text, origin, self.principal, self.signing_key,
            trust_level=trust,
        )
        session_ctx.add(seg)

        if is_tainted:
            from tessera.events import EventKind, SecurityEvent, emit
            emit(SecurityEvent.now(
                kind=EventKind.CONTENT_INJECTION_DETECTED,
                principal=self.principal,
                detail={
                    "scanner": "mesh_proxy",
                    "tool_name": tool_name,
                    "heuristic_regex": h_regex,
                    "heuristic_window": h_window,
                    "directive_score": d_result.score,
                    "schema_score": s_result.score,
                },
            ))

        return output_text, trust

    def check_mcp_server(self, server_uri: str) -> tuple[bool, str]:
        """Check if an MCP server is on the allowlist."""
        if self._mcp_allowlist is None:
            return True, "no allowlist configured"
        if self._mcp_allowlist.is_allowed(server_uri):
            return True, "allowed"
        return False, f"MCP server {server_uri!r} not on allowlist"

    def check_tool_definition(
        self, server_uri: str, tool_name: str, definition: str,
    ) -> bool:
        """Check for rug-pull and tool description poisoning."""
        changed = self._definition_tracker.has_changed(server_uri, tool_name, definition)
        # Scan for tool description poisoning regardless of change
        from tessera.scanners.tool_descriptions import scan_tool
        poison_result = scan_tool(tool_name, definition)
        if poison_result.poisoned:
            from tessera.events import EventKind, SecurityEvent, emit
            emit(SecurityEvent.now(
                kind=EventKind.CONTENT_INJECTION_DETECTED,
                principal=self.principal,
                detail={
                    "scanner": "tool_description",
                    "tool_name": tool_name,
                    "server_uri": server_uri,
                    "severity": poison_result.max_severity.value,
                    "matches": len(poison_result.matches),
                },
            ))
        return changed or poison_result.poisoned

    def check_tool_shadows(
        self,
        server_tools: dict[str, list[str]],
    ) -> dict[str, Any]:
        """Detect cross-server tool name shadowing (typosquatting).

        Args:
            server_tools: Mapping of server_name to list of tool names.

        Returns:
            Shadow scan result with detected pairs.
        """
        from tessera.scanners.tool_shadow import scan_cross_server_shadows
        result = scan_cross_server_shadows(server_tools, principal=self.principal)
        return {
            "shadowed": result.shadowed,
            "pairs": [
                {
                    "tool_a": p.tool_a, "server_a": p.server_a,
                    "tool_b": p.tool_b, "server_b": p.server_b,
                    "distance": p.distance,
                }
                for p in result.pairs
            ],
        }

    def add_user_prompt(
        self, prompt: str, session_id: str = "default",
    ) -> tuple[bool, str]:
        """Add a user prompt to a session's context, with optional screening.

        Returns (passed, reason). If screening fails, the prompt is still
        added but labeled UNTRUSTED to prevent a phished prompt from
        carrying USER trust.
        """
        session_ctx = self._contexts.get(session_id)
        if self.enable_prompt_screening:
            from tessera.scanners.prompt_screen import screen_and_emit
            result = screen_and_emit(prompt, principal=self.principal)
            if not result.passed:
                seg = make_segment(
                    prompt, Origin.USER, self.principal, self.signing_key,
                    trust_level=TrustLevel.UNTRUSTED,
                )
                session_ctx.add(seg)
                return False, f"prompt screening failed: {result.reason}"

        # Check for delegated prompt injection (instructions from external content)
        if self._identity is not None:
            delegation = self._identity.detect_delegation(prompt)
            if delegation["detected"] and delegation["requires_confirmation"]:
                seg = make_segment(
                    prompt, Origin.USER, self.principal, self.signing_key,
                    trust_level=TrustLevel.TOOL,
                )
                session_ctx.add(seg)
                return True, f"delegation detected: {delegation['source_description']}"

        seg = make_segment(prompt, Origin.USER, self.principal, self.signing_key)
        session_ctx.add(seg)
        return True, "clean"

    def build_provenance_manifest(
        self, session_id: str = "default",
    ) -> dict[str, Any]:
        """Build a signed provenance manifest for a session's current context."""
        from tessera.provenance import ContextSegmentEnvelope, PromptProvenanceManifest
        session_ctx = self._contexts.get(session_id)
        envelopes = [
            ContextSegmentEnvelope.from_segment(
                seg, issuer=self.principal, key=self.signing_key,
            )
            for seg in session_ctx.segments
        ]
        if not envelopes:
            return {"segments": 0, "manifest": None}
        manifest = PromptProvenanceManifest.assemble(
            envelopes, assembled_by=self.principal, key=self.signing_key,
        )
        return {"segments": len(envelopes), "manifest": manifest.to_dict()}

    def split_context(self, session_id: str = "default") -> dict[str, Any]:
        """Split a session's context into trusted and untrusted halves."""
        from tessera.quarantine import split_by_trust
        trusted, untrusted = split_by_trust(self._contexts.get(session_id))
        return {
            "trusted_segments": len(trusted.segments),
            "untrusted_segments": len(untrusted.segments),
            "trusted_min_trust": int(trusted.min_trust),
            "untrusted_min_trust": int(untrusted.min_trust) if untrusted.segments else 0,
        }

    def export_evidence(self) -> dict[str, Any]:
        """Flush the evidence buffer and return a signed evidence bundle."""
        from tessera.evidence import EvidenceBundle, HMACEvidenceSigner
        bundle = EvidenceBundle.from_buffer(self._evidence_buffer)
        signer = HMACEvidenceSigner(key=self.signing_key, issuer=self.principal)
        signed = signer.sign(bundle)
        return signed.to_dict()

    def resolve_approval(
        self,
        session_id: str,
        approved: bool,
        approver: str,
        reason: str = "",
    ) -> dict[str, Any]:
        """Resolve a pending approval request."""
        decision = self._session_store.resolve(session_id, approved, approver, reason)
        if not approved:
            self._cooldown.record_denial()
        return {
            "resolved": True,
            "approved": approved,
            "approver": approver,
            "escalation_level": self._cooldown.state().level,
        }

    def check_output_provenance(
        self, model_response: str, user_task: str = "",
        session_id: str = "default",
    ) -> dict:
        """Post-generation check for output manipulation, scoped to a session.

        Detects when injected content influences the model's text response
        (the travel-injection attack class where there is no tool call to
        block but the model echoes attacker content).
        """
        from tessera.output_monitor import check_output_integrity
        result = check_output_integrity(
            model_response,
            self._contexts.get(session_id),
            user_task=user_task,
        )
        return {
            "safe": result.action != "block",
            "action": result.action,
            "score": result.score,
            "patterns": list(result.patterns_matched),
        }

    def check_canary_leakage(
        self, model_response: str, session_id: str = "default",
    ) -> list[dict]:
        """Check if model response contains canary tokens from a session's tainted segments."""
        sess_state = self._session_states.get(session_id)
        if sess_state is None or sess_state.canary_tracker is None:
            return []
        influences = sess_state.canary_tracker.check_response(model_response)
        return [
            {
                "segment_id": inf.segment_id,
                "canary_token": inf.canary_token,
                "was_directive": inf.was_directive,
            }
            for inf in influences
        ]

    def register_secret(self, name: str, value: str) -> None:
        """Register a secret for automatic redaction from tool outputs."""
        if self._secret_registry is not None:
            self._secret_registry.add(name, value)

    def reset_context(self, session_id: str = "default") -> None:
        """Drop a single session's state. Other sessions are untouched.

        Clears the session's Context, accumulator, risk forecaster, and
        canary tracker (via the SessionContextStore eviction callback)
        and resets the sensitivity HWM for that session.
        """
        self._contexts.reset(session_id)
        if self._hwm is not None:
            self._hwm.reset(session_id)

    def reset_all_sessions(self) -> None:
        """Drop every session. Useful for tests and operator-driven resets.

        Resets the HWM for each session id known to the context store
        before dropping the contexts; sessions whose HWM was set without
        ever calling :meth:`add_user_prompt` (e.g. via direct
        ``/v1/sensitivity/classify`` calls) won't be reset here. Use
        :meth:`reset_context` for those individually.
        """
        if self._hwm is not None:
            for sid in self._contexts.session_ids():
                self._hwm.reset(sid)
        self._contexts.reset_all()

    @property
    def context(self) -> Context:
        """The default-session Context.

        Backward-compat alias for ``self._contexts.get("default")``. New
        callers should pass an explicit ``session_id`` to the methods
        that take it (``add_user_prompt``, ``scan_and_label``,
        ``evaluate_tool_call``, ``split_context``,
        ``build_provenance_manifest``) so cross-session isolation holds.
        """
        return self._contexts.get("default")

    @property
    def contexts(self):
        """The full :class:`SessionContextStore` for inspection / GC."""
        return self._contexts

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def audit_chain_valid(self) -> bool:
        """Verify the tamper-evident audit chain."""
        return self._audit_log.verify_chain()

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    def _current_policy_candidate(self, envelope: Any) -> Any:
        """Built-in replay candidate: what would the current Policy decide?

        Rebuilds a :class:`Context` from the envelope's recorded segments
        (trust levels are what drives policy; content is SHA-256 only, so
        we use that as the placeholder text), then calls
        ``self._policy.evaluate``. Returns a
        :class:`tessera.replay.PolicyDecision`.

        This does NOT run scanners, guardrail, sensitivity HWM, or risk
        forecasting. Those are outputs of the request, not inputs to the
        taint-tracking policy check; replaying them would require the
        original plaintext. What this answers is the narrow but useful
        question: "given the trust-label shape of the original request,
        would my current Policy rules still produce the recorded verdict?"
        """
        from tessera.labels import Origin, TrustLevel
        from tessera.policy import DecisionKind
        from tessera.replay import PolicyDecision

        ctx = Context()
        for seg in envelope.segments:
            try:
                level = TrustLevel(int(seg.get("trust_level", 0)))
            except (ValueError, TypeError):
                level = TrustLevel.UNTRUSTED
            placeholder = str(seg.get("content_sha256", ""))
            ctx.add(make_segment(
                placeholder,
                Origin.WEB,
                self.principal,
                key=self.signing_key,
                trust_level=level,
            ))
        decision = self._policy.evaluate(
            context=ctx,
            tool_name=envelope.tool_name,
            args=envelope.args,
        )
        return PolicyDecision(
            allowed=decision.kind == DecisionKind.ALLOW,
            reason=decision.reason,
            source="agentmesh.proxy.current_policy",
        )

    def set_audit_label(self, seq: int, record_hash: str, label: str) -> dict[str, Any]:
        """Set (or update) the ground-truth label for an audit record."""
        from tessera.replay import Label
        lbl = Label(label)
        self._label_store.set(seq, record_hash, lbl)
        if self.audit_label_path is not None:
            self._label_store.dump(self.audit_label_path)
        return {"seq": seq, "hash": record_hash, "label": lbl.value}

    # ------------------------------------------------------------------
    # HTTP API
    # ------------------------------------------------------------------

    def build_app(self) -> Any:
        """Build a FastAPI app with mesh proxy endpoints."""
        from fastapi import FastAPI, Header
        from typing import Optional

        app = FastAPI(title="AgentMesh Proxy", version="0.10.0")
        proxy = self

        @app.get("/healthz")
        def healthz():
            default_ctx = proxy._contexts.get("default")
            return {
                "status": "ok",
                "service": "agentmesh-proxy",
                "version": "0.10.0",
                # Default session is shown for backward compat; for the
                # full picture across tenants, see /v1/sessions.
                "context_segments": len(default_ctx.segments),
                "min_trust": int(default_ctx.min_trust),
                "active_sessions": len(proxy._contexts),
                "session_evictions": proxy._contexts.evictions,
                "guardrail_enabled": proxy._guardrail is not None,
                "guardrail_breaker": (
                    proxy._guardrail.stats.get("breaker")
                    if proxy._guardrail is not None else None
                ),
                "identity_required": proxy.require_identity,
                "rate_limiter_active": proxy._rate_limiter is not None,
                "mcp_allowlist_active": proxy._mcp_allowlist is not None,
                "audit_chain_valid": proxy.audit_chain_valid,
                "prompt_screening": proxy.enable_prompt_screening,
                "trust_decay": proxy.enable_trust_decay,
                "risk_forecasting": proxy.enable_risk_forecasting,
                "plan_verification": proxy.enable_plan_verification,
                "canary_tokens": proxy.enable_canary_tokens,
                "cel_rules": proxy._policy.cel_engine is not None,
            }

        @app.post("/v1/evaluate")
        def api_evaluate(body: _EvalRequest):
            session_ctx = proxy._contexts.get(body.session_id)
            if body.user_prompt and not session_ctx.segments:
                proxy.add_user_prompt(body.user_prompt, session_id=body.session_id)
            allowed, reason = proxy.evaluate_tool_call(
                body.tool_name, body.args,
                session_id=body.session_id,
                agent_identity=body.agent_identity,
                delegation_token_str=body.delegation_token,
            )
            return {
                "allowed": allowed,
                "reason": reason,
                "session_id": body.session_id,
                "trust_level": int(session_ctx.min_trust),
            }

        @app.post("/v1/scan")
        def api_scan(body: _ScanRequest):
            from tessera.scanners.directive import scan_directive as _d
            from tessera.scanners.heuristic import injection_scores as _s

            h_r, h_w = _s(body.text)
            d = _d(body.text)
            tainted = h_r >= 0.9 or d.detected
            return {
                "tainted": tainted,
                "trust_level": 0 if tainted else 100,
                "heuristic_score": max(h_r, h_w),
                "directive_score": d.score,
            }

        @app.post("/v1/label")
        def api_label(body: _ScanRequest):
            _, trust = proxy.scan_and_label(
                body.tool_name, body.text, session_id=body.session_id,
            )
            session_ctx = proxy._contexts.get(body.session_id)
            return {
                "trust_level": int(trust),
                "session_id": body.session_id,
                "context_segments": len(session_ctx.segments),
                "min_trust": int(session_ctx.min_trust),
            }

        @app.get("/v1/policy")
        def api_policy():
            reqs = {}
            for key, r in proxy._policy.requirements.items():
                name, _ = key
                reqs[name] = {
                    "required_trust": int(r.required_trust),
                    "side_effects": r.side_effects,
                }
            approval = list(proxy._policy._human_approval_tools)
            return {
                "default_trust": int(proxy._policy.default_required_trust),
                "requirements": reqs,
                "human_approval_tools": approval,
            }

        @app.get("/v1/context")
        def api_context(session_id: str = "default"):
            """Snapshot of one session's Context.

            Pass ``session_id`` to inspect a specific tenant; without
            it, returns the default session. Sessions are isolated:
            two tenants on the same proxy never share segments.
            """
            ctx = proxy._contexts.get(session_id)
            return {
                "session_id": session_id,
                "segments": len(ctx.segments),
                "min_trust": int(ctx.min_trust),
                "max_trust": int(ctx.max_trust),
            }

        @app.post("/v1/reset")
        def api_reset(session_id: str = "default"):
            """Drop one session. Other sessions are untouched."""
            proxy.reset_context(session_id)
            return {"status": "context reset", "session_id": session_id}

        @app.get("/v1/sessions")
        def api_sessions():
            """List active session ids and the store's eviction stats."""
            store = proxy._contexts
            return {
                "count": len(store),
                "session_ids": store.session_ids(),
                "evictions": store.evictions,
                "ttl_seconds": proxy.session_context_ttl_seconds,
                "max_sessions": proxy.session_context_max,
            }

        @app.get("/v1/rate-limit/{session_id}")
        def api_rate_limit(session_id: str):
            status = proxy._rate_limiter.status(session_id)
            return {
                "session_id": status.session_id,
                "calls_in_window": status.calls_in_window,
                "calls_remaining": status.calls_remaining,
                "max_calls": status.max_calls,
                "exceeded": status.exceeded,
            }

        @app.post("/v1/check-server")
        def api_check_server(body: _CheckServerRequest):
            allowed, reason = proxy.check_mcp_server(body.server_uri)
            return {"allowed": allowed, "reason": reason}

        @app.get("/v1/audit")
        def api_audit():
            return {
                "chain_valid": proxy.audit_chain_valid,
                "entries": len(proxy._audit_log.entries),
                "timestamps_valid": proxy._audit_log.verify_timestamps()[0],
                "sequences_valid": proxy._audit_log.verify_sequences(),
            }

        @app.post("/v1/check-output")
        def api_check_output(
            body: _CheckOutputRequest, session_id: str = "default",
        ):
            """Post-generation output provenance and integrity check.

            Scoped to ``session_id``; the canary leakage check only
            matches tokens that were injected for the same session.
            """
            provenance = proxy.check_output_provenance(
                body.response, body.user_task, session_id=session_id,
            )
            canary = proxy.check_canary_leakage(body.response, session_id=session_id)
            return {
                "session_id": session_id,
                "provenance": provenance,
                "canary_leakage": canary,
                "safe": provenance["safe"] and len(canary) == 0,
            }

        @app.get("/v1/xds/snapshot")
        def api_xds_snapshot():
            """Serve current policy as an xDS-compatible snapshot.

            This is a simplified REST fallback for environments that cannot
            run the gRPC xDS server. Production deployments should use the
            gRPC xDS endpoint in tessera.xds.
            """
            reqs = {}
            for key, r in proxy._policy.requirements.items():
                name, _ = key
                reqs[name] = {
                    "required_trust": int(r.required_trust),
                    "side_effects": r.side_effects,
                }
            cel_rules = []
            if proxy._policy.cel_engine is not None:
                cel_rules = [
                    {"name": r.name, "expression": r.expression}
                    for r in proxy._policy.cel_engine._rules
                ]
            return {
                "version": "v1",
                "default_trust": int(proxy._policy.default_required_trust),
                "requirements": reqs,
                "human_approval_tools": list(proxy._policy._human_approval_tools),
                "cel_rules": cel_rules,
                "rate_limit": {
                    "max_calls": proxy.rate_limit_calls,
                    "burst": proxy.rate_limit_burst,
                },
                "features": {
                    "trust_decay": proxy.enable_trust_decay,
                    "risk_forecasting": proxy.enable_risk_forecasting,
                    "plan_verification": proxy.enable_plan_verification,
                    "canary_tokens": proxy.enable_canary_tokens,
                    "prompt_screening": proxy.enable_prompt_screening,
                    "secret_redaction": proxy.enable_secret_redaction,
                },
            }

        # -- Tier A+B endpoints --

        @app.get("/v1/provenance")
        def api_provenance(session_id: str = "default"):
            """Build and return a signed provenance manifest for one session."""
            return proxy.build_provenance_manifest(session_id=session_id)

        @app.get("/v1/context/split")
        def api_context_split(session_id: str = "default"):
            """Split one session's context into trusted / untrusted halves."""
            return proxy.split_context(session_id=session_id)

        @app.get("/v1/evidence")
        def api_evidence():
            """Export signed evidence bundle from event buffer."""
            return proxy.export_evidence()

        @app.get("/v1/audit/verify")
        def api_audit_verify():
            """Verify the hash-chained audit log end-to-end.

            Walks the configured ``audit_log_path``. If a ``seal_key``
            was configured at startup the companion .seal file is also
            checked (truncation detection).

            Returns 404-shaped JSON when no persistent log is configured
            so operators can distinguish "not configured" from "empty file."
            """
            if proxy._audit_sink is None:
                return {
                    "configured": False,
                    "path": None,
                    "valid": None,
                    "records_checked": 0,
                }
            from tessera.audit_log import verify_chain
            result = verify_chain(
                proxy.audit_log_path,
                seal_key=proxy.audit_log_seal_key,
            )
            return {
                "configured": True,
                "path": proxy.audit_log_path,
                "valid": result.valid,
                "records_checked": result.records_checked,
                "first_bad_seq": result.first_bad_seq,
                "reason": result.reason,
                "seal_valid": result.seal_valid,
                "last_seq": proxy._audit_sink.last_seq,
                "last_hash": proxy._audit_sink.last_hash,
            }

        @app.get("/v1/audit/cases")
        def api_audit_cases(
            kinds: str | None = None,
            trajectory_id: str | None = None,
            since: str | None = None,
            until: str | None = None,
            limit: int = 100,
        ):
            """List replayable cases from the audit log.

            Only records whose ``detail`` carries a ``replay`` envelope
            appear here. ``kinds`` is comma-separated. ``since``/``until``
            are ISO-8601. Each case entry carries its current label (or
            ``unreviewed``) so UIs can render ground-truth status
            alongside the decision.
            """
            if proxy._audit_sink is None:
                return {"configured": False, "cases": []}
            from datetime import datetime
            from tessera.replay import iter_replay_cases
            kind_list = [k.strip() for k in kinds.split(",")] if kinds else None
            since_dt = datetime.fromisoformat(since) if since else None
            until_dt = datetime.fromisoformat(until) if until else None
            cases = []
            for case in iter_replay_cases(
                proxy.audit_log_path,
                kinds=kind_list,
                since=since_dt,
                until=until_dt,
                trajectory_id=trajectory_id,
            ):
                label = proxy._label_store.get(case.seq, case.record_hash)
                cases.append({
                    "seq": case.seq,
                    "hash": case.record_hash,
                    "timestamp": case.timestamp,
                    "trajectory_id": case.envelope.trajectory_id,
                    "tool_name": case.envelope.tool_name,
                    "decision_allowed": case.envelope.decision_allowed,
                    "decision_source": case.envelope.decision_source,
                    "decision_reason": case.envelope.decision_reason,
                    "sensitivity_hwm": case.envelope.sensitivity_hwm,
                    "label": label.value,
                })
                if len(cases) >= limit:
                    break
            return {"configured": True, "cases": cases, "count": len(cases)}

        @app.post("/v1/audit/label")
        def api_audit_label(body: _LabelRequest):
            """Attach a ground-truth label to an audit record.

            Label values: ``correct``, ``incorrect``, ``unreviewed``.
            Persisted to ``audit_label_path`` if configured. Labels are
            keyed by ``(seq, hash)`` so they survive chain migrations;
            a stale hash yields ``unreviewed`` on subsequent reads.
            """
            try:
                return proxy.set_audit_label(body.seq, body.hash, body.label)
            except ValueError as e:
                return {"error": str(e)}

        @app.get("/v1/audit/labels")
        def api_audit_labels():
            """Return the full label map."""
            raw = proxy._label_store.all()
            return {
                "path": proxy.audit_label_path,
                "labels": {
                    str(seq): {"hash": h, "label": lbl.value}
                    for seq, (h, lbl) in raw.items()
                },
            }

        @app.get("/v1/replay/candidates")
        def api_replay_candidates():
            """Available built-in replay candidates."""
            return {
                "candidates": [
                    {
                        "name": "current_policy",
                        "description": (
                            "Re-runs the proxy's current Policy against each "
                            "envelope's recorded trust-label shape."
                        ),
                    },
                ],
            }

        @app.post("/v1/replay/run")
        def api_replay_run(body: _ReplayRequest):
            """Replay historical decisions against a candidate policy.

            Returns aggregate stats plus a per-case summary. Only
            ``current_policy`` is built in; external tooling can pull
            ``/v1/audit/cases`` and run any candidate of its own.
            """
            if proxy._audit_sink is None:
                return {"configured": False}
            if body.candidate != "current_policy":
                return {
                    "error": f"unknown candidate: {body.candidate}",
                    "available": ["current_policy"],
                }
            from datetime import datetime
            from tessera.replay import run_replay
            since_dt = datetime.fromisoformat(body.since) if body.since else None
            until_dt = datetime.fromisoformat(body.until) if body.until else None
            stats, results = run_replay(
                proxy.audit_log_path,
                proxy._current_policy_candidate,
                labels=proxy._label_store,
                kinds=body.kinds,
                since=since_dt,
                until=until_dt,
                trajectory_id=body.trajectory_id,
            )
            return {
                "candidate": body.candidate,
                "stats": {
                    "total": stats.total,
                    "agreed": stats.agreed,
                    "disagreed": stats.disagreed,
                    "errored": stats.errored,
                    "flipped_allow_to_deny": stats.flipped_allow_to_deny,
                    "flipped_deny_to_allow": stats.flipped_deny_to_allow,
                    "labels": stats.labels,
                    "fixed": stats.fixed,
                    "regressed": stats.regressed,
                },
                "results": [
                    {
                        "seq": r.case.seq,
                        "hash": r.case.record_hash,
                        "trajectory_id": r.case.envelope.trajectory_id,
                        "tool_name": r.case.envelope.tool_name,
                        "original_allowed": r.case.envelope.decision_allowed,
                        "agreement": r.agreement.value,
                        "new_allowed": (
                            r.new_decision.allowed
                            if r.new_decision is not None else None
                        ),
                        "new_reason": (
                            r.new_decision.reason
                            if r.new_decision is not None else None
                        ),
                        "error": r.error,
                        "label": proxy._label_store.get(
                            r.case.seq, r.case.record_hash,
                        ).value,
                    }
                    for r in results
                ],
            }

        @app.post("/v1/policy/builder/run")
        def api_policy_builder_run(body: _PolicyBuilderRequest):
            """Analyze the audit log and return scored policy proposals.

            Reads the persistent audit log, aggregates per-tool counts
            against the in-memory :class:`LabelStore`, and returns a list
            of proposals ranked by net leverage (``fixed - regressed``).
            Each entry includes the proposal's diff and the full replay
            stats so operators can review before applying.

            This is read-only. Apply a proposal by editing the policy
            YAML by hand and reloading; intentional gap so the proxy
            does not silently mutate live policy.
            """
            if proxy._audit_sink is None:
                return {"configured": False}
            from tessera.policy_builder import analyze_and_score
            impacts = analyze_and_score(
                proxy.audit_log_path,
                current_policy=proxy._policy,
                labels=proxy._label_store,
                min_label_signal=body.min_label_signal,
            )
            return {
                "configured": True,
                "count": len(impacts),
                "proposals": [
                    {
                        "kind": i.proposal.kind.value,
                        "tool_name": i.proposal.tool_name,
                        "summary": i.proposal.summary,
                        "rationale": i.proposal.rationale,
                        "diff": i.proposal.diff,
                        "current_required_trust": (
                            i.proposal.current_required_trust.name
                        ),
                        "proposed_required_trust": (
                            i.proposal.proposed_required_trust.name
                        ),
                        "evidence": {
                            "total_observations": (
                                i.proposal.evidence.total_observations
                            ),
                            "denied": i.proposal.evidence.denied,
                            "allowed": i.proposal.evidence.allowed,
                            "labeled_correct_denials": (
                                i.proposal.evidence.labeled_correct_denials
                            ),
                            "labeled_incorrect_denials": (
                                i.proposal.evidence.labeled_incorrect_denials
                            ),
                            "labeled_correct_allows": (
                                i.proposal.evidence.labeled_correct_allows
                            ),
                            "labeled_incorrect_allows": (
                                i.proposal.evidence.labeled_incorrect_allows
                            ),
                        },
                        "impact": {
                            "total": i.stats.total,
                            "agreed": i.stats.agreed,
                            "disagreed": i.stats.disagreed,
                            "errored": i.stats.errored,
                            "fixed": i.stats.fixed,
                            "regressed": i.stats.regressed,
                            "net_fixes": i.net_fixes,
                            "flipped_allow_to_deny": (
                                i.stats.flipped_allow_to_deny
                            ),
                            "flipped_deny_to_allow": (
                                i.stats.flipped_deny_to_allow
                            ),
                        },
                    }
                    for i in impacts
                ],
            }

        @app.post("/v1/policy/builder/llm")
        def api_policy_builder_llm(body: _PolicyBuilderLLMRequest):
            """Generate proposals via the LLM proposer, optionally scored.

            Reuses the same Anthropic / OpenAI client and model that
            backs the LLMGuardrail. Returns 503-shaped JSON when the
            guardrail isn't configured, since this endpoint shares the
            judge endpoint trust boundary.

            Templates the LLM may emit:
              - tighten / loosen required_trust by one step
              - mark_read_only (side_effects=False)
              - register_tool with a starting required_trust

            The deterministic baseline at /v1/policy/builder/run runs
            independently and is what operators should trust by default;
            this endpoint adds suggestions the heuristics cannot derive.
            """
            if proxy._audit_sink is None:
                return {"configured": False}
            if proxy._guardrail is None:
                return {
                    "configured": True,
                    "llm_available": False,
                    "reason": "guardrail_provider not configured",
                }
            from tessera.policy_builder import score_proposal
            from tessera.policy_builder_llm import LLMPolicyProposer
            proposer = LLMPolicyProposer(
                client=proxy._guardrail._client,
                model=proxy._guardrail._model,
                client_type=proxy._guardrail._client_type,
            )
            proposals = proposer.propose(
                proxy.audit_log_path,
                current_policy=proxy._policy,
                labels=proxy._label_store,
            )
            scored = []
            for p in proposals:
                entry = {
                    "kind": p.kind.value,
                    "tool_name": p.tool_name,
                    "summary": p.summary,
                    "rationale": p.rationale,
                    "diff": p.diff,
                    "current_required_trust": p.current_required_trust.name,
                    "proposed_required_trust": p.proposed_required_trust.name,
                }
                if body.score:
                    impact = score_proposal(
                        p, proxy.audit_log_path,
                        labels=proxy._label_store,
                    )
                    entry["impact"] = {
                        "total": impact.stats.total,
                        "agreed": impact.stats.agreed,
                        "disagreed": impact.stats.disagreed,
                        "errored": impact.stats.errored,
                        "fixed": impact.stats.fixed,
                        "regressed": impact.stats.regressed,
                        "net_fixes": impact.net_fixes,
                    }
                scored.append(entry)
            return {
                "configured": True,
                "llm_available": True,
                "model": proxy._guardrail._model,
                "breaker_state": proposer.breaker_state.state,
                "count": len(scored),
                "proposals": scored,
            }

        @app.get("/v1/metrics/guardrail")
        def api_guardrail_metrics():
            """LLM guardrail call, cache, and circuit-breaker metrics.

            Operators should alert when ``breaker.state != "closed"`` or
            ``breaker.total_opens`` rises. ``skipped_by_breaker`` growing
            without ``breaker.state`` reporting open means half-open
            probes are failing; investigate upstream before re-enabling.
            """
            if proxy._guardrail is None:
                return {"enabled": False}
            return {"enabled": True, **proxy._guardrail.stats}

        @app.post("/v1/approve")
        def api_approve(body: _ApprovalRequest):
            """Resolve a pending human approval request."""
            return proxy.resolve_approval(
                body.session_id, body.approved, body.approver,
            )

        @app.get("/v1/audit/sarif")
        def api_sarif():
            """Export security events as SARIF 2.1.0 JSON."""
            if proxy._exports is None:
                return {"error": "exports not configured"}
            return proxy._exports.export_sarif()

        @app.post("/v1/rag/scan")
        def api_rag_scan(body: _RAGScanRequest):
            """Scan RAG retrieval chunks for injection."""
            if proxy._transport is None:
                return {"error": "RAG guard not enabled"}
            return proxy._transport.scan_rag_chunk(body.text, body.source_id, body.user_prompt)

        @app.post("/v1/mcp/baseline")
        def api_mcp_baseline(body: _MCPBaselineRequest):
            """Snapshot current tool definitions for drift detection."""
            if proxy._transport is None:
                return {"error": "transport not enabled"}
            return proxy._transport.snapshot_baseline(body.tools, body.server_name)

        @app.post("/v1/mcp/drift")
        def api_mcp_drift(body: _MCPBaselineRequest):
            """Check current tools against baseline for drift."""
            if proxy._transport is None:
                return {"error": "transport not enabled"}
            return proxy._transport.check_drift(body.tools, body.server_name)

        @app.post("/v1/tool-shadows")
        def api_tool_shadows(body: _ToolShadowRequest):
            """Check for cross-server tool name shadowing."""
            return proxy.check_tool_shadows(body.server_tools)

        @app.get("/v1/liveness/{agent_id}")
        def api_liveness(agent_id: str):
            """Check liveness state for an agent."""
            if proxy._identity is None:
                return {"agent_id": agent_id, "alive": True, "tracked": False}
            return proxy._identity.liveness_state(agent_id)

        @app.post("/v1/heartbeat")
        def api_heartbeat(body: _HeartbeatRequest):
            """Record a heartbeat for an agent."""
            if proxy._identity is not None:
                proxy._identity.heartbeat(body.agent_id)
            return {"status": "ok", "agent_id": body.agent_id}

        @app.post("/v1/supply-chain/check")
        def api_supply_chain_check(body: _ScanRequest):
            """Scan a command or manifest for supply chain attack patterns."""
            result = proxy._supply_chain_scanner.scan(
                tool_name=body.tool_name or "raw",
                args=body.text,
            )
            return {
                "allowed": result.allowed,
                "primary_reason": result.primary_reason,
                "max_severity": result.max_severity,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "message": f.message,
                        "arg_path": f.arg_path,
                        "evidence": f.evidence,
                        "metadata": f.metadata,
                    }
                    for f in result.findings
                ],
            }

        @app.post("/v1/url-rules/check")
        def api_url_rules_check(body: _URLRulesCheckRequest):
            """Evaluate a URL+method against the static rules engine.

            Returns the first decisive verdict (allow / deny) plus the
            rule_id that produced it, or ``no_match`` to signal that
            the slower checks (SSRF, scanners, LLM judge) would run
            in evaluate_tool_call.
            """
            decision = proxy._url_rules.evaluate(body.url, method=body.method)
            return {
                "configured": proxy._url_rules.rule_count > 0,
                "rule_count": proxy._url_rules.rule_count,
                "verdict": decision.verdict.value,
                "rule_id": decision.rule_id,
                "description": decision.description,
                "url": decision.url,
                "method": decision.method,
            }

        @app.post("/v1/ssrf/check")
        def api_ssrf_check(body: _SSRFCheckRequest):
            """Check a single URL against the SSRF guard.

            Returns the verdict plus all findings (cloud metadata,
            private IP, scheme, etc.). Hostnames are resolved before
            the CIDR check, so DNS-rebinding-style payloads that
            ultimately point at internal IPs are caught.
            """
            result = proxy._ssrf_guard.check_url(body.url)
            return {
                "allowed": result.allowed,
                "primary_reason": result.primary_reason,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "category": f.category,
                        "message": f.message,
                        "url": f.url,
                        "resolved_ip": f.resolved_ip,
                        "arg_path": f.arg_path,
                    }
                    for f in result.findings
                ],
            }

        @app.post("/v1/destructive/check")
        def api_destructive_check(body: _ScanRequest):
            """Check a command or SQL for destructive patterns.

            Returns the matched pattern with its stable id, category, and
            arg_path so audit logs can pinpoint which argument triggered.
            """
            result = proxy._destructive_guard.check(
                body.tool_name or "$raw",
                body.text,
            )
            return {
                "allowed": result.allowed,
                "primary_reason": result.primary_reason,
                "matches": [
                    {
                        "pattern_id": m.pattern_id,
                        "category": m.category,
                        "description": m.description,
                        "arg_path": m.arg_path,
                        "matched_text": m.matched_text,
                    }
                    for m in result.matches
                ],
            }

        @app.post("/v1/sensitivity/classify")
        def api_sensitivity_classify(body: _ClassifyRequest):
            """Classify content and optionally update a trajectory HWM.

            If ``trajectory_id`` is provided, the HWM for that trajectory
            is updated to max(current, classified_label). This is the
            ONLY endpoint that mutates the HWM; keeps the evaluator's
            read audit-pure.
            """
            result = proxy._classifier.classify(body.content)
            response: dict[str, Any] = {
                "label": result.label.name,
                "label_rank": int(result.label),
                "matched_rule_ids": list(result.matched_rule_ids),
            }
            if body.trajectory_id:
                new_mark = proxy._hwm.observe(body.trajectory_id, result.label)
                response["trajectory_id"] = body.trajectory_id
                response["high_water_mark"] = new_mark.name
                response["high_water_mark_rank"] = int(new_mark)
            return response

        @app.get("/v1/sensitivity/status")
        def api_sensitivity_status(trajectory_id: str = "default"):
            """Current high-water mark for a trajectory."""
            mark = proxy._hwm.get(trajectory_id)
            return {
                "trajectory_id": trajectory_id,
                "high_water_mark": mark.name,
                "high_water_mark_rank": int(mark),
            }

        @app.delete("/v1/sensitivity/status")
        def api_sensitivity_reset(trajectory_id: str):
            """Clear HWM for a completed trajectory. Idempotent."""
            proxy._hwm.reset(trajectory_id)
            return {"trajectory_id": trajectory_id, "reset": True}

        # Mount xDS server endpoints if enabled
        if proxy._exports is not None:
            proxy._exports.mount_xds_endpoints(app)

        return app

    def run(self, host: str = "0.0.0.0", port: int = 9090) -> None:
        import uvicorn

        app = self.build_app()
        features = []
        if self.require_identity:
            features.append("identity")
        if self._guardrail:
            features.append("guardrail")
        if self._mcp_allowlist:
            features.append("allowlist")
        features.append(f"rate-limit({self.rate_limit_calls}/window)")
        if self.enable_prompt_screening:
            features.append("prompt-screening")
        if self._secret_registry and len(self._secret_registry) > 0:
            features.append("secret-redaction")
        if self.enable_trust_decay:
            features.append("trust-decay")
        if self.enable_risk_forecasting:
            features.append("risk-forecasting")
        if self.enable_plan_verification:
            features.append("plan-verification")
        if self.enable_canary_tokens:
            features.append("canary-tokens")
        if self._policy.cel_engine is not None:
            features.append("cel-rules")

        print(f"AgentMesh proxy starting on {host}:{port}")
        print(f"Upstream: {self.upstream_url}")
        print(f"Features: {', '.join(features)}")
        uvicorn.run(app, host=host, port=port, log_level="info")


def main() -> None:
    """CLI entry point."""
    allowlist_raw = os.environ.get("AGENTMESH_MCP_ALLOWLIST", "")
    allowlist = [p.strip() for p in allowlist_raw.split(",") if p.strip()] if allowlist_raw else []

    def _bool_env(key: str, default: str = "false") -> bool:
        return os.environ.get(key, default).lower() == "true"

    proxy = MeshProxy(
        upstream_url=os.environ.get("AGENTMESH_UPSTREAM_URL", "http://localhost:3000"),
        policy_path=os.environ.get("AGENTMESH_POLICY_PATH", "policy.yaml"),
        signing_key=os.environ.get("AGENTMESH_SIGNING_KEY", "default").encode(),
        principal=os.environ.get("AGENTMESH_PRINCIPAL", "agentmesh-proxy"),
        guardrail_provider=os.environ.get("AGENTMESH_GUARDRAIL_PROVIDER"),
        guardrail_model=os.environ.get("AGENTMESH_GUARDRAIL_MODEL"),
        require_identity=_bool_env("AGENTMESH_REQUIRE_IDENTITY"),
        mcp_allowlist_patterns=allowlist,
        rate_limit_calls=int(os.environ.get("AGENTMESH_RATE_LIMIT", "50")),
        rate_limit_burst=int(os.environ.get("AGENTMESH_BURST_LIMIT", "10")),
        # Tier 2
        enable_prompt_screening=_bool_env("AGENTMESH_PROMPT_SCREENING", "true"),
        enable_secret_redaction=_bool_env("AGENTMESH_SECRET_REDACTION", "true"),
        enable_pii_scanning=_bool_env("AGENTMESH_PII_SCANNING"),
        # Tier 3
        enable_trust_decay=_bool_env("AGENTMESH_TRUST_DECAY"),
        enable_risk_forecasting=_bool_env("AGENTMESH_RISK_FORECASTING", "true"),
        enable_plan_verification=_bool_env("AGENTMESH_PLAN_VERIFICATION", "true"),
        enable_canary_tokens=_bool_env("AGENTMESH_CANARY_TOKENS"),
        cel_rules_path=os.environ.get("AGENTMESH_CEL_RULES_PATH"),
    )
    port = int(os.environ.get("AGENTMESH_PORT", "9090"))
    proxy.run(port=port)


if __name__ == "__main__":
    main()
