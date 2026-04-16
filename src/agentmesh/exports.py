"""Compliance export, telemetry, and policy distribution.

Groups seven Tessera modules:
- tessera.compliance_sarif (SARIFCorrelator)
- tessera.events_sarif (SARIFSink)
- tessera.telemetry (emit_decision, proxy_request_span)
- tessera.confidence (classify_confidence, enrich_with_confidence)
- tessera.control_plane (HMACControlPlaneSigner, SignedControlPlaneDocument)
- tessera.xds.server (XDSServer)
- tessera.xds.client (XDSClient)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ComplianceExporter:
    """SARIF export, telemetry spans, and xDS policy distribution.

    Args:
        signing_key: HMAC key for signing control plane documents.
        principal: Proxy principal name.
        enable_sarif: Register a SARIFSink for event export.
        enable_telemetry: Wrap pipeline steps with OTel spans.
        enable_xds_server: Mount xDS gRPC-compatible REST endpoints.
    """

    signing_key: bytes
    principal: str
    enable_sarif: bool = True
    enable_telemetry: bool = False
    enable_xds_server: bool = False

    _sarif_sink: Any = field(default=None, init=False, repr=False)
    _correlator: Any = field(default=None, init=False, repr=False)
    _cp_signer: Any = field(default=None, init=False, repr=False)
    _xds_server: Any = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.enable_sarif:
            from tessera.events_sarif import SARIFSink
            from tessera.events import register_sink
            self._sarif_sink = SARIFSink(
                tool_name="agentmesh",
                tool_version="0.3.0",
            )
            register_sink(self._sarif_sink)

            from tessera.compliance_sarif import SARIFCorrelator
            self._correlator = SARIFCorrelator()

        from tessera.control_plane import HMACControlPlaneSigner
        self._cp_signer = HMACControlPlaneSigner(
            key=self.signing_key,
            issuer=self.principal,
        )

        if self.enable_xds_server:
            try:
                from tessera.xds.server import XDSServer
                self._xds_server = XDSServer()
            except ImportError:
                pass

    def export_sarif(self) -> dict[str, Any]:
        """Export all collected security events as SARIF 2.1.0 JSON."""
        if self._sarif_sink is None:
            return {"error": "SARIF sink not enabled"}
        return self._sarif_sink.to_sarif()

    def sign_document(
        self,
        document_type: str,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        """Sign a control plane document with HMAC.

        Args:
            document_type: Type identifier (e.g., "policy", "registry").
            document: The document payload.

        Returns:
            Signed document dict with signature metadata.
        """
        signed = self._cp_signer.sign(document_type, document)
        return signed.to_dict()

    def enrich_event(
        self,
        event: Any,
        confidence: float,
    ) -> dict[str, Any]:
        """Add confidence tier metadata to a security event.

        Args:
            event: SecurityEvent instance.
            confidence: Score 0.0-1.0.

        Returns:
            Event dict with confidence and confidence_tier fields.
        """
        from tessera.confidence import enrich_with_confidence
        return enrich_with_confidence(event, confidence)

    def classify_confidence(self, score: float) -> str:
        """Classify a confidence score into a tier label.

        Returns one of: BLOCK, WARN, INFO, SUPPRESS.
        """
        from tessera.confidence import classify_confidence
        return classify_confidence(score).name

    def update_xds_policy(self, policy_dict: dict[str, Any]) -> None:
        """Push a policy update to the xDS server snapshot."""
        if self._xds_server is None:
            return
        from tessera.xds.server import TYPE_POLICY_BUNDLE
        self._xds_server.set_resource(
            TYPE_POLICY_BUNDLE,
            "default",
            policy_dict,
        )

    def mount_xds_endpoints(self, app: Any) -> None:
        """Mount xDS REST endpoints on a FastAPI app."""
        if self._xds_server is not None:
            self._xds_server.add_to_app(app)

    @property
    def telemetry_enabled(self) -> bool:
        """Check if OpenTelemetry is available and enabled."""
        if not self.enable_telemetry:
            return False
        try:
            from tessera.telemetry import is_enabled
            return is_enabled()
        except ImportError:
            return False

    def emit_decision_span(self, decision: Any) -> None:
        """Emit an OTel span for a policy decision (no-op if disabled)."""
        if not self.telemetry_enabled:
            return
        from tessera.telemetry import emit_decision
        emit_decision(decision)
