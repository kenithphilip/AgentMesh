"""AgentMesh adapter shims that swap in alternative primitive backends.

Exposes :class:`tessera_rs` adapters for AgentMesh callers that
want the Rust fast path (`pip install tessera-rs`). The adapters
mirror the Python ``tessera`` API surface AgentMesh's proxy expects
so the swap is safe per call site.
"""

from __future__ import annotations

__all__: list[str] = []
