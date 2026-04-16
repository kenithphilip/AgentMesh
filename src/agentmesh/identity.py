"""Identity, signing, and liveness for the AgentMesh proxy.

Groups six Tessera modules into a single provider:
- tessera.signing (HMACSigner, HMACVerifier)
- tessera.identity (JWTAgentIdentityVerifier, AgentIdentity)
- tessera.mtls (extract_peer_identity, MTLSPeerIdentity)
- tessera.spire (create_spire_identity_verifier)
- tessera.liveness (LivenessChecker)
- tessera.delegation_intent (detect_delegation)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class IdentityProvider:
    """Unified identity provider for agent authentication and signing.

    Args:
        signing_key: HMAC key for label signing.
        principal: Default principal name for this proxy.
        trust_domain: SPIFFE trust domain for identity verification.
        spire_socket: Path to the SPIRE Workload API socket (optional).
        enable_liveness: Track agent heartbeats and enforce TTL.
        allowed_trust_domains: Trust domains accepted for mTLS peers.
    """

    signing_key: bytes
    principal: str
    trust_domain: str = "agentmesh.local"
    spire_socket: str | None = None
    enable_liveness: bool = True
    allowed_trust_domains: list[str] = field(default_factory=list)

    _signer: Any = field(default=None, init=False, repr=False)
    _verifier: Any = field(default=None, init=False, repr=False)
    _identity_verifier: Any = field(default=None, init=False, repr=False)
    _liveness: Any = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        from tessera.signing import HMACSigner, HMACVerifier

        self._signer = HMACSigner(key=self.signing_key)
        self._verifier = HMACVerifier(key=self.signing_key)

        if self.enable_liveness:
            from tessera.liveness import LivenessChecker
            self._liveness = LivenessChecker()

        if self.spire_socket:
            try:
                from tessera.spire import create_spire_identity_verifier
                self._identity_verifier = create_spire_identity_verifier(
                    socket_path=self.spire_socket,
                    expected_trust_domain=self.trust_domain,
                )
            except (ImportError, Exception):
                pass

    def sign_label(self, label: Any, content: str) -> Any:
        """Sign a TrustLabel with the configured HMAC key."""
        return self._signer.sign(label, content)

    def verify_label(self, label: Any, content: str) -> bool:
        """Verify a TrustLabel signature."""
        return self._verifier.verify(label, content)

    def verify_agent(
        self,
        token: str,
        audience: str = "agentmesh",
    ) -> Any | None:
        """Verify an agent identity token (JWT-SVID or plain JWT).

        Returns an AgentIdentity on success, None on failure.
        """
        if self._identity_verifier is None:
            return None
        try:
            return self._identity_verifier.verify(token, audience=audience)
        except Exception:
            return None

    def extract_peer(
        self,
        scope: dict[str, Any],
        headers: dict[str, str],
    ) -> Any | None:
        """Extract mTLS peer identity from ASGI scope or XFCC headers.

        Returns MTLSPeerIdentity or None.
        """
        try:
            from tessera.mtls import extract_peer_identity
            return extract_peer_identity(
                scope=scope,
                headers=headers,
                allowed_trust_domains=self.allowed_trust_domains,
            )
        except (ImportError, Exception):
            return None

    def heartbeat(self, agent_id: str) -> None:
        """Record a heartbeat for an agent."""
        if self._liveness is not None:
            self._liveness.heartbeat(agent_id)

    def is_alive(self, agent_id: str) -> bool:
        """Check if an agent has a recent heartbeat."""
        if self._liveness is None:
            return True
        return self._liveness.is_alive(agent_id)

    def liveness_state(self, agent_id: str) -> dict[str, Any]:
        """Get liveness state for an agent."""
        if self._liveness is None:
            return {"agent_id": agent_id, "alive": True, "tracked": False}
        state = self._liveness.state(agent_id)
        return {
            "agent_id": state.agent_id,
            "alive": state.alive,
            "suspended": state.suspended,
            "ttl_seconds": state.ttl_seconds,
        }

    def detect_delegation(self, prompt: str) -> dict[str, Any]:
        """Check if a user prompt delegates to external content.

        Returns delegation scope with detected phrases.
        """
        from tessera.delegation_intent import detect_delegation
        scope = detect_delegation(prompt)
        return {
            "detected": scope.detected,
            "source_description": scope.source_description,
            "delegation_phrases": list(scope.delegation_phrases),
            "requires_confirmation": scope.requires_confirmation,
        }
