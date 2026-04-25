# Changelog

All notable changes to AgentMesh are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Everything before v1.0.0 is experimental; API changes may occur in any
minor release.

## [0.10.0] - 2026-04-25

Requires `tessera-mesh>=1.0.0` (Tessera GA).

### Added

- **`RustProvenanceLabelAdapter`** in
  `agentmesh.adapters.tessera_rs` that wraps the v1.0
  `tessera_rs.label.ProvenanceLabel` PyO3 binding (Wave 4B in the
  Tessera v0.12-to-v1.0 plan). Ships four surfaces:
  `trusted_user`, `untrusted_tool_output`, `join`, and
  `to_canonical_json` plus three numeric accessors
  (`integrity_numeric`, `secrecy_numeric`, `capacity_numeric`).
- `_TesseraRsBundle.label` and `_TesseraRsBundle.label_available`
  flag for AgentMesh callers that want to gate the fast path on
  the v1.0 wheel being installed.
- Five parity tests in `tests/test_tessera_rs_adapter.py` covering
  trusted-user / untrusted-tool-output construction, the
  max-integrity join law, canonical-JSON source preservation,
  the Python-fallback path for non-default `secrecy`, and the
  mixed-backend join rejection.

### Changed

- `tessera-mesh` dependency pin raised to `>=1.0.0` so users get
  the v1.0 GA library by default. Older `tessera-mesh>=0.7.1`
  installs still work; `RustProvenanceLabelAdapter` falls back to
  Python when the `tessera_rs.label` submodule is absent.
- `agentmesh-proxy` `/healthz` `version` field now reports
  `0.10.0` (was stuck at `0.7.1` since v0.7.1).
- FastAPI app `version` raised from `0.3.0` to `0.10.0`.

### Verified

- `pytest tests/test_tessera_rs_adapter.py -v` passes 5 new label
  tests + the existing parity matrix when `tessera-rs>=1.0.0` is
  installed; the `label` tests skip cleanly on older wheels.
- Smoke-tested on `tessera-rs` built from
  `Tessera/rust/crates/tessera-py` at workspace v1.0.0.

## [0.9.0] - 2026-04-24

Requires `tessera-mesh>=0.7.1`.

### Added

- Deeper `tessera_rs` auto-swap when `use_rust_primitives=True`:
  rate limiter + `PyScanner` registry now route through the Rust
  fast path. New `RustToolCallRateLimitAdapter` mirrors the
  Python `tessera.ratelimit.ToolCallRateLimit` surface, with a
  Python fallback for `tessera-rs<0.11.0`.
- `PyScanner` parity tests cover heuristic-injection scoring and
  the unicode-tag scanner.

## [0.8.0] - 2026-04-23

Requires `tessera-mesh>=0.7.1`.

### Added

- `agentmesh.adapters.tessera_rs` module exposing
  `RustContextAdapter`, `RustPolicyAdapter`,
  `RustJsonlHashchainSinkAdapter`, `RustSsrfGuardAdapter`,
  `RustUrlRulesEngineAdapter`, `RustCelPolicyEngineAdapter` plus
  helper functions `rust_canonical_json`,
  `rust_injection_score`, `rust_scan_unicode_tags`. Activated by
  passing `use_rust_primitives=True` to `MeshProxy`; falls back
  transparently to Python for surfaces tessera_rs does not yet
  cover.
- README and docs note the optional `tessera-rs` PyO3 wheel as
  the Rust fast path.

## [0.7.1] - 2026-04-23

Requires `tessera-mesh>=0.7.1`.

### Fixed

- **Multi-tenant Context isolation.** v0.7.0 and earlier shared one
  `Context` across all sessions. Combined with the taint-tracking
  invariant (`min_trust` over every segment drives the verdict), this
  meant a web-tainted segment from session A would deny tool calls
  from session B running on the same proxy. v0.7.1 keeps each session's
  Context, `DependencyAccumulator`, risk forecaster, and canary tracker
  isolated. Cross-session interference cannot happen.

### Added

- `MeshProxy.session_context_ttl_seconds` and
  `MeshProxy.session_context_max` config fields control the per-session
  state lifetime and the LRU cap.
- `GET /v1/sessions` returns active session ids, eviction count, and
  the configured limits.
- `MeshProxy.reset_all_sessions()` for operator-driven full reset.
- `_PerSessionState` dataclass groups the adjacent per-session
  resources (accumulator + forecaster + canary tracker) so they are
  created and dropped atomically.

### Changed

- `MeshProxy.add_user_prompt`, `build_provenance_manifest`,
  `split_context`, `check_output_provenance`, and
  `check_canary_leakage` now take `session_id: str = "default"`.
- `MeshProxy.context` property remains a backward-compat alias for
  `self._contexts.get("default")`.
- The endpoints `/v1/context`, `/v1/context/split`, `/v1/provenance`,
  `/v1/check-output`, and `/v1/reset` accept `session_id` as a query
  parameter; `/v1/evaluate` and `/v1/label` accept it in the request
  body. Omitting `session_id` defaults to the literal session named
  `default` for backward compat.
- `MeshClient` propagates its `session_id` field through every
  endpoint call (previously only `evaluate` and `add_prompt` did).
- `MeshProxy` no longer holds standalone `_accumulator`,
  `_risk_forecaster`, or `_canary_tracker` attributes. Tests that
  checked these need to read `proxy._get_session_state(session_id)`
  instead.
- The proxy's `version` field in `/healthz` now reads `0.7.1`.

### Verified

- 240 passing tests; same 2 pre-existing async-fixture failures as
  v0.7.0.
- 16 new tests in `test_session_isolation.py` covering the headline
  bug (alice's taint does not deny bob), per-session accumulator /
  forecaster / canary isolation, eviction callback cleanup, every
  endpoint that accepts `session_id`, and backward compatibility for
  callers that omit `session_id`.

## [0.7.0] - 2026-04-22

Requires `tessera-mesh>=0.7.0`.

### Added

- `LLMGuardrail` circuit breaker exposed on `/healthz` and a new
  `GET /v1/metrics/guardrail` endpoint. Operators can now alert on
  `breaker.state != "closed"` or rising `breaker.total_opens`.
- Persistent hash-chained audit log via `audit_log_path` (and optional
  `audit_log_seal_key` for truncation detection). Backed by
  `tessera.audit_log.JSONLHashchainSink`. New `GET /v1/audit/verify`
  walks the chain and returns `valid` / `first_bad_seq` / `seal_valid`.
- Replay system over the audit log:
  - `GET /v1/audit/cases` filtered case listing with current label per
    case
  - `POST /v1/audit/label` set ground-truth label, persists to disk
  - `GET /v1/audit/labels` dump label map
  - `GET /v1/replay/candidates` list built-in candidates
  - `POST /v1/replay/run` replay against a candidate, return stats and
    per-case results
  - Built-in `current_policy` candidate rebuilds a `Context` from the
    recorded segments and runs `Policy.evaluate`.
- SSRF guard wired into the evaluator after destructive_guard /
  supply_chain and before YARA. New endpoint `POST /v1/ssrf/check`
  for direct queries. Three new config flags: `enable_ssrf_guard`,
  `ssrf_blocked_hostnames`, `ssrf_allowlist_hostnames`.
- `guardrail_redact_before_judge: bool = True` toggle. Default
  preserves the invariant that no live secret reaches the judge
  endpoint; opt-out only when the operator trusts the judge at the
  same level as the application LLM. The choice is recorded in each
  guardrail event detail under `redacted_input`.
- Policy builder workflow:
  - `POST /v1/policy/builder/run` returns scored proposals from the
    deterministic analyzer ranked by `net_fixes` (fixed - regressed)
  - `POST /v1/policy/builder/llm` returns LLM-generated proposals
    (constrained template set), optionally scored. Reuses the same
    Anthropic / OpenAI client and model that backs the LLMGuardrail.
- Static URL pattern rules gate. Fast deterministic allow / deny that
  runs before SSRF and scanners. New endpoint
  `POST /v1/url-rules/check`. Two new config flags: `enable_url_rules`,
  `url_rules` (list of dicts with `rule_id`, `pattern`, `kind`,
  `action`, optional `methods`, optional `description`).

### Changed

- `LLMGuardrail` parse failures now raise so the circuit breaker counts
  them (previous behavior silently fell back to `confidence=0.0`).
- `scan_and_label` snapshots `output_text` before any redaction phase
  so the raw form survives subsequent mutation.

### Verified

- 226 passing tests; 2 pre-existing failures are environmental
  (`pytest-asyncio` not configured for the NeMo tests).
- All new endpoints have integration tests against the FastAPI app.
- Suites pass on both repos with the same 5 pre-existing environmental
  failures, zero new regressions.
