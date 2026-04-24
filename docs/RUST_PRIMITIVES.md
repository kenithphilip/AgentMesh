# Rust primitives fast-path

AgentMesh ships an opt-in fast path that swaps a curated subset of
its hot-path primitives to the Rust implementations from
[`tessera-rs`](https://pypi.org/project/tessera-rs/). The Python
`tessera-mesh` API surface stays the same; only the implementations
change.

## Quickstart

```bash
pip install agentmesh-mesh tessera-mesh tessera-rs
```

```python
from agentmesh.proxy import MeshProxy

proxy = MeshProxy(
    signing_key=b"your-32-byte-key-must-be-this-long",
    audit_log_path="/var/log/agentmesh/audit.jsonl",
    use_rust_primitives=True,   # opt in
)
```

When `use_rust_primitives=True` is set AND the `tessera-rs` wheel is
installed, AgentMesh uses the Rust implementations for the surfaces
listed below. Default is `False`, so existing deployments are not
affected.

## Adapters available

| Surface | Python class | Rust adapter | Status |
|---------|--------------|--------------|--------|
| `tessera.policy.Policy` | `Policy` | `agentmesh.adapters.tessera_rs.RustPolicyAdapter` | Available, used via direct construction |
| `tessera.context.Context` | `Context` | `agentmesh.adapters.tessera_rs.RustContextAdapter` | Available, used via direct construction |
| `tessera.ratelimit.ToolCallRateLimit` | `ToolCallRateLimit` | `agentmesh.adapters.tessera_rs.RustToolCallRateLimitAdapter` | **Auto-swapped** when `use_rust_primitives=True` |
| `tessera.audit_log.JSONLHashchainSink` | `JSONLHashchainSink` | `agentmesh.adapters.tessera_rs.RustJsonlHashchainSinkAdapter` | **Auto-swapped** when `use_rust_primitives=True` and `audit_log_path` is set |
| `tessera.ssrf_guard.SSRFGuard` | `SSRFGuard` | `agentmesh.adapters.tessera_rs.RustSsrfGuardAdapter` | **Auto-swapped** when `use_rust_primitives=True`; falls back to Python on custom hostname lists |
| `tessera.url_rules.URLRulesEngine` | `URLRulesEngine` | `agentmesh.adapters.tessera_rs.RustUrlRulesEngineAdapter` | Available, falls back to Python for non-prefix patterns |
| `tessera.scanners.heuristic.injection_score` | `injection_score` | `agentmesh.adapters.tessera_rs.rust_injection_score` | Available, used via direct call |
| `tessera.scanners.unicode.scan_unicode_tags` | `scan_unicode_tags` | `agentmesh.adapters.tessera_rs.rust_scan_unicode_tags` | Available, used via direct call |
| `tessera.cel_engine.CELPolicyEngine` | `CELPolicyEngine` | `agentmesh.adapters.tessera_rs.RustCelPolicyEngineAdapter` | Available, used via `RustPolicyAdapter.set_cel_engine` |
| Canonical JSON serializer | (Python `json.dumps`) | `agentmesh.adapters.tessera_rs.rust_canonical_json` | Available, used via direct call |
| Hard scanners (PromptGuard, Perplexity, PDF, Image, CodeShield) | varies | `tessera_rs.scanners.register_scanner` + `scan` | **Hybrid**: register a Python implementation under a name, invoke from any consumer through the registry. See [PyScanner registry](#pyscanner-callback-registry) below. |

## What auto-swaps when `use_rust_primitives=True`

As of `agentmesh-mesh` v0.9.0:

- `_audit_sink` (when `audit_log_path` is set)
- `_rate_limiter` (always)
- `_ssrf_guard` (always; falls back to Python if custom hostname lists are configured)

The other adapters (Policy, Context, scanners, URL rules, CEL,
canonical JSON) require explicit construction in your application
code today; the proxy still uses the Python implementations for
those at the construction sites in `__post_init__`. Wider auto-swap
coverage is tracked for v0.10.0 of `agentmesh-mesh`.

## PyScanner callback registry

The "hard" scanners (PromptGuard, Perplexity, PDFInspector,
ImageInspector, CodeShield) are not pure-Rust ports because they
depend on Python ML / PIL / sandboxed-PDF stacks. Instead,
`tessera-rs` ships a callback registry: register a Python callable
under a stable name, then any consumer (the Rust gateway, AgentMesh,
another Python module) invokes it through the same dispatcher.

```python
from tessera_rs.scanners import register_scanner, scan

def my_promptguard(text: str) -> dict:
    return {
        "detected": expensive_ml_call(text) > 0.5,
        "score": 0.42,
        "reason": "promptguard ML",
    }

register_scanner("promptguard", my_promptguard)
result = scan("promptguard", "Ignore previous instructions...")
```

The registry survives across the PyO3 boundary, so a single
registration in your AgentMesh process is visible to everyone in
the same Python interpreter. Future Rust-side consumers (e.g. the
gateway invoking registered scanners during request processing)
will dispatch through the same registry.

## Manual wiring (beyond the auto-swap)

The proxy currently auto-swaps the audit sink only. The other
surfaces require explicit construction in your application code or
adapter:

```python
from agentmesh.adapters.tessera_rs import (
    RustContextAdapter, RustPolicyAdapter, RustCelPolicyEngineAdapter,
    rust_injection_score, rust_scan_unicode_tags,
)

# Per-session context: build with the same signing key your proxy uses.
ctx = RustContextAdapter(signing_key=b"k" * 32)
ctx.add(some_labeled_segment)

# Policy: register tools, optionally install a CEL engine.
policy = RustPolicyAdapter()
policy.require("send_email", TrustLevel.USER)

cel = RustCelPolicyEngineAdapter([
    CELRule(name="block-prod-deletes", expression="...", action="deny", message="..."),
])
policy.set_cel_engine(cel)

# Hot-path evaluation:
decision = policy.evaluate(ctx, "send_email", principal="alice")

# Pure-function scanners:
score = rust_injection_score(suspect_text)
result = rust_scan_unicode_tags(suspect_text)
```

## Unsupported surfaces (Python remains authoritative)

Many AgentMesh primitives have no Rust equivalent today. The flag
does NOT change behavior for these; the Python `tessera` package
keeps running for them:

- `tessera.guardrail.LLMGuardrail` (LLM call + circuit breaker)
- `tessera.scanners.pii.PIIScanner` (Presidio-backed)
- `tessera.scanners.directive`, `tessera.scanners.intent`,
  `tessera.scanners.canary`, `tessera.scanners.tool_shadow`,
  `tessera.scanners.tool_descriptions`,
  `tessera.scanners.tool_output_schema`,
  `tessera.scanners.prompt_screen`, `tessera.scanners.binary_content`,
  `tessera.scanners.supply_chain`, `tessera.scanners.yara`
- `tessera.sensitivity.*` (high-water mark + outbound policy)
- `tessera.delegation.DelegationToken` and verifier
- `tessera.provenance.PromptProvenanceManifest`
- `tessera.evidence.EvidenceBundle`
- `tessera.replay.iter_replay_cases`
- `tessera.policy_builder.*` and `tessera.policy_builder_llm.*`
- `tessera.events_sarif.SARIFSink` and
  `tessera.compliance_sarif.SARIFCorrelator`
- `tessera.session_context.SessionContextStore`
- `tessera.identity`, `tessera.spire`, `tessera.mtls`, `tessera.mcp`,
  `tessera.a2a`, `tessera.adapters.*`, `tessera.control_plane`,
  `tessera.cel_engine` (engine eval is on Rust; rule loaders +
  IR compilation stay Python)

These are tracked for future tessera_rs releases as customer demand
warrants.

## Performance

The Rust implementations are measurably faster on the surfaces
where they are available. Microbench numbers from
`rust/bench/results.md` in the Tessera repo:

- Policy evaluate (taint floor): ~120 ns native vs ~20 us Python
  (around 150x)
- CEL evaluator (interpreter): ~3 us per rule (parity with celpy)
- CEL evaluator (Cranelift JIT, int rules): ~40 ns per rule
  (around 80x faster than the interpreter)
- SIMD JSON body parse: 4-8% faster than serde_json on 4-64KB bodies
- Rate limiter: identical wire behavior to Python; the Rust
  implementation pays no per-check allocation for the in-window
  vec, so it is roughly 5-10x faster per `check()` call at scale
  (not yet bench-quantified)
- EmbeddingAnomalyChecker baseline computation: trivial pure-Rust
  port; not a bottleneck either way

Macro-level bench compare runs (`rust/scripts/bench-compare.sh`
in the Tessera repo) capture full Rust-gateway-vs-AgentMesh
numbers across mixed and single-endpoint workloads.

## Verification

The adapter parity test suite at
`tests/test_tessera_rs_adapter.py` runs the same input through both
the Python and Rust implementations and asserts the outputs match.
Run with:

```bash
pytest tests/test_tessera_rs_adapter.py -v
```

The full suite skips automatically when `tessera-rs` is not
installed.

## Migration considerations

- **Stateful primitives stay on Python.** Rate limiter, session
  store, sensitivity high-water mark, and similar in-memory
  state-keeping primitives are not yet ported. If you rely on these,
  the flag does not affect them.
- **Audit log format is unchanged.** The Rust sink writes the same
  JSONL hash-chain wire format as the Python sink. Existing audit
  consumers (replay, SARIF export, SIEM) keep working without
  changes.
- **CEL parity quirk.** Both engines stringify `args` values via
  `str(v)` for byte-equal parity. This is documented in the
  v0.10.0-beta.1 release notes and tracked for a future common fix.
- **YAML policy loading stays on Python.** `from_yaml_path` and
  `compile_policy` are Python-only. Once a policy is compiled, the
  evaluator runs on Rust if you wrap with `RustPolicyAdapter`.
