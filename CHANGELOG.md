# Changelog

All notable changes to AgentMesh are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Everything before v1.0.0 is experimental; API changes may occur in any
minor release.

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
