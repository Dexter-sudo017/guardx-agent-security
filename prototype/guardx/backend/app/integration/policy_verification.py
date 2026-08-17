from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Callable, Protocol

from app.contracts.executor_integration import ExecutorServiceRequest


@dataclass(frozen=True)
class PolicyVerification:
    verified: bool
    attestation_reference: str | None = None
    reason: str = ""


def policy_action_hash(request: ExecutorServiceRequest) -> str:
    """Bind the policy record to the complete proposed action, excluding only approval resume state."""
    value = {
        "session_id": request.session_id,
        "authorization_decision": request.authorization_decision.model_dump(mode="json"),
        "capability": request.capability,
        "tool": request.tool,
        "target": request.target,
        "arguments": request.arguments,
        "evidence_context": request.evidence_context,
    }
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class PolicyDecisionVerifier(Protocol):
    def verify(self, request: ExecutorServiceRequest) -> PolicyVerification: ...


@dataclass(frozen=True)
class StaticPolicyAttestation:
    action_hash: str
    attestation_reference: str


class StaticPolicyDecisionVerifier:
    """Test/dev verifier backed by exact full-action attestations."""

    def __init__(self, attestations: list[StaticPolicyAttestation] | None = None) -> None:
        self._attestations = list(attestations or [])

    def attest(self, request: ExecutorServiceRequest, *, reference: str | None = None) -> StaticPolicyAttestation:
        attestation = StaticPolicyAttestation(
            action_hash=policy_action_hash(request),
            attestation_reference=reference or f"policy-attestation://{request.session_id}/{policy_action_hash(request)}",
        )
        self._attestations.append(attestation)
        return attestation

    def verify(self, request: ExecutorServiceRequest) -> PolicyVerification:
        if request.action_origin.authority != "policy_engine" or not request.action_origin.trusted:
            return PolicyVerification(False, None, "origin is not the trusted policy engine")
        observed = policy_action_hash(request)
        for attestation in self._attestations:
            if observed == attestation.action_hash:
                return PolicyVerification(True, attestation.attestation_reference, "authoritative full-action attestation matched")
        return PolicyVerification(False, None, "no authoritative full-action attestation matched")


class CallbackPolicyDecisionVerifier:
    """Production port for Core v2 policy-store/attestation verification."""

    def __init__(self, callback: Callable[[ExecutorServiceRequest], PolicyVerification]) -> None:
        self._callback = callback

    def verify(self, request: ExecutorServiceRequest) -> PolicyVerification:
        return self._callback(request)
