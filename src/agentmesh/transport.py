"""MCP transport, baseline drift detection, and RAG guard.

Groups three Tessera modules:
- tessera.mcp (MCPInterceptor, MCPSecurityContext)
- tessera.mcp_baseline (MCPBaseline, DriftPolicy)
- tessera.rag_guard (RAGRetrievalGuard, RetrievalPatternTracker)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class MCPTransport:
    """MCP transport layer with baseline tracking and RAG protection.

    Args:
        upstream_url: SSE endpoint of the upstream MCP server.
        principal: Proxy principal for labeling.
        signing_key: HMAC key for segment signing.
        rag_taint_threshold: Score above which RAG chunks are tainted.
        rag_reject_threshold: Score above which RAG chunks are rejected.
    """

    upstream_url: str
    principal: str
    signing_key: bytes
    rag_taint_threshold: float = 0.65
    rag_reject_threshold: float = 0.85

    _baselines: dict[str, Any] = field(default_factory=dict, init=False, repr=False)
    _rag_guard: Any = field(default=None, init=False, repr=False)
    _retrieval_tracker: Any = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        from tessera.rag_guard import RAGRetrievalGuard, RetrievalPatternTracker

        self._rag_guard = RAGRetrievalGuard(
            taint_threshold=self.rag_taint_threshold,
            reject_threshold=self.rag_reject_threshold,
            emit_events=True,
        )
        self._retrieval_tracker = RetrievalPatternTracker()

    def snapshot_baseline(
        self,
        tools: list[dict[str, Any]],
        server_name: str = "default",
    ) -> dict[str, Any]:
        """Snapshot current tool definitions for baseline drift detection.

        Args:
            tools: List of tool definition dicts (name, description, inputSchema).
            server_name: Identifier for the MCP server.

        Returns:
            Baseline metadata dict.
        """
        from tessera.mcp_baseline import MCPBaseline

        baseline = MCPBaseline.snapshot(tools, server_name)
        self._baselines[server_name] = baseline
        return baseline.to_dict()

    def check_drift(
        self,
        current_tools: list[dict[str, Any]],
        server_name: str = "default",
    ) -> dict[str, Any]:
        """Check current tools against stored baseline for drift.

        Returns:
            Drift result with list of modified/added/removed tools.
        """
        baseline = self._baselines.get(server_name)
        if baseline is None:
            return {"drifted": False, "reason": "no baseline stored"}

        result = baseline.check_and_emit(current_tools, principal=self.principal)
        return {
            "drifted": result.drifted,
            "drifts": [
                {
                    "tool_name": d.tool_name,
                    "kind": d.kind,
                }
                for d in result.drifts
            ],
            "baseline_tool_count": result.baseline_tool_count,
            "current_tool_count": result.current_tool_count,
        }

    def scan_rag_chunk(
        self,
        text: str,
        source_id: str = "unknown",
        user_prompt: str | None = None,
    ) -> dict[str, Any]:
        """Scan a single RAG retrieval chunk for injection.

        Args:
            text: The retrieved chunk text.
            source_id: Identifier for the source document.
            user_prompt: The user's query for intent comparison.

        Returns:
            Scan result with action recommendation.
        """
        result = self._rag_guard.scan_chunk(text, source_id, user_prompt)
        self._retrieval_tracker.record(source_id, user_prompt or "")
        return {
            "safe": result.safe,
            "action": result.action.value,
            "max_score": result.max_score,
            "source_id": result.source_id,
            "suspicious_source": self._retrieval_tracker.is_suspicious(source_id),
        }

    def scan_rag_batch(
        self,
        chunks: list[tuple[str, str]],
        user_prompt: str | None = None,
    ) -> list[dict[str, Any]]:
        """Scan a batch of RAG chunks.

        Args:
            chunks: List of (text, source_id) pairs.
            user_prompt: The user's query.

        Returns:
            List of scan results.
        """
        results = self._rag_guard.scan_batch(chunks, user_prompt)
        out = []
        for r in results:
            self._retrieval_tracker.record(r.source_id, user_prompt or "")
            out.append({
                "safe": r.safe,
                "action": r.action.value,
                "max_score": r.max_score,
                "source_id": r.source_id,
            })
        return out

    @property
    def rag_stats(self) -> dict[str, int]:
        """Cumulative RAG scanning statistics."""
        return self._rag_guard.stats

    def build_security_context(
        self,
        delegation: Any = None,
        manifest: Any = None,
        envelopes: tuple = (),
    ) -> Any:
        """Build an MCPSecurityContext for upstream calls.

        Args:
            delegation: Optional DelegationToken.
            manifest: Optional PromptProvenanceManifest.
            envelopes: Tuple of ContextSegmentEnvelopes.

        Returns:
            MCPSecurityContext instance.
        """
        from tessera.mcp import MCPSecurityContext
        return MCPSecurityContext(
            delegation=delegation,
            provenance_manifest=manifest,
            segment_envelopes=envelopes,
        )
