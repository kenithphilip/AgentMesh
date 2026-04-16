"""HTTP client for the AgentMesh proxy.

All framework SDK adapters use this client to call the proxy endpoints
instead of importing Tessera directly. This decouples agent code from
the security library, letting the proxy handle scanning, taint tracking,
and policy evaluation as infrastructure.

Usage::

    from agentmesh.client import MeshClient

    mesh = MeshClient("http://localhost:9090")
    mesh.add_prompt("Find hotels in Paris and email me the best one")
    mesh.label("search_hotels", hotel_data)

    ok, reason = mesh.evaluate("send_email", args={"to": "boss@corp.com"})
    if not ok:
        print(f"Blocked: {reason}")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class MeshClient:
    """Synchronous client for the AgentMesh proxy HTTP API.

    Args:
        base_url: Proxy base URL (e.g., "http://localhost:9090").
        session_id: Session identifier for rate limiting and state.
        agent_identity: JWT-SVID or SPIFFE ID for identity verification.
        timeout: HTTP request timeout in seconds.
    """

    base_url: str = "http://localhost:9090"
    session_id: str = "default"
    agent_identity: str | None = None
    timeout: float = 10.0

    _http: httpx.Client = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self._http = httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout,
        )

    def close(self) -> None:
        """Close the underlying HTTP connection."""
        if self._http:
            self._http.close()

    def __enter__(self) -> MeshClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # -- Core pipeline --

    def health(self) -> dict[str, Any]:
        """Check proxy health and feature flags."""
        return self._get("/healthz")

    def add_prompt(self, prompt: str) -> dict[str, Any]:
        """Add a user prompt to the proxy context.

        The proxy screens the prompt for delegated injection before
        adding it to the context.
        """
        return self._post("/v1/evaluate", {
            "tool_name": "_prompt",
            "user_prompt": prompt,
            "session_id": self.session_id,
            "agent_identity": self.agent_identity,
        })

    def evaluate(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        """Evaluate whether a tool call is allowed.

        Returns (allowed, reason).
        """
        payload: dict[str, Any] = {
            "tool_name": tool_name,
            "session_id": self.session_id,
            "agent_identity": self.agent_identity,
        }
        if args:
            payload["args"] = args
        r = self._post("/v1/evaluate", payload)
        return r.get("allowed", False), r.get("reason", "unknown")

    def label(self, tool_name: str, output_text: str) -> dict[str, Any]:
        """Scan and label tool output, adding it to the context.

        The proxy runs all scanners (heuristic, directive, intent,
        unicode, PII, secret redaction) and returns the trust level.
        """
        return self._post("/v1/label", {
            "text": output_text,
            "tool_name": tool_name,
        })

    def scan(self, text: str, tool_name: str = "unknown") -> dict[str, Any]:
        """Quick injection scan without labeling or context update."""
        return self._post("/v1/scan", {
            "text": text,
            "tool_name": tool_name,
        })

    def reset(self) -> dict[str, Any]:
        """Reset the proxy context for a new session."""
        return self._post("/v1/reset", {})

    # -- Observability --

    def context(self) -> dict[str, Any]:
        """Get current context state (segment count, trust levels)."""
        return self._get("/v1/context")

    def audit(self) -> dict[str, Any]:
        """Get audit chain status."""
        return self._get("/v1/audit")

    def sarif(self) -> dict[str, Any]:
        """Export security events as SARIF 2.1.0 JSON."""
        return self._get("/v1/audit/sarif")

    def evidence(self) -> dict[str, Any]:
        """Export signed evidence bundle."""
        return self._get("/v1/evidence")

    def provenance(self) -> dict[str, Any]:
        """Get signed provenance manifest for the current context."""
        return self._get("/v1/provenance")

    # -- RAG guard --

    def scan_rag(
        self,
        text: str,
        source_id: str = "unknown",
        user_prompt: str | None = None,
    ) -> dict[str, Any]:
        """Scan a RAG retrieval chunk for injection."""
        return self._post("/v1/rag/scan", {
            "text": text,
            "source_id": source_id,
            "user_prompt": user_prompt,
        })

    # -- Output verification --

    def check_output(
        self,
        response: str,
        user_task: str = "",
    ) -> dict[str, Any]:
        """Post-generation output integrity and canary check."""
        return self._post("/v1/check-output", {
            "response": response,
            "user_task": user_task,
        })

    # -- Agent liveness --

    def heartbeat(self) -> dict[str, Any]:
        """Send a heartbeat for this agent."""
        agent_id = self.agent_identity or self.session_id
        return self._post("/v1/heartbeat", {"agent_id": agent_id})

    # -- Internal HTTP helpers --

    def _get(self, path: str) -> dict[str, Any]:
        r = self._http.get(path)
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        r = self._http.post(path, json=data)
        r.raise_for_status()
        return r.json()
