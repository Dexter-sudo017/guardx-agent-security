from __future__ import annotations

import hashlib
import json
from typing import Any

from app.capabilities import CapabilityStore
from app.contracts import (
    ActionOrigin,
    AuthorizationDecisionContract,
    ContextualAuthorizationRequest,
    ExecutorServiceRequest,
    PolicyV2Result,
)
from app.integration.capability import CapabilityVerification
from app.integration.executor_service import ExecutorIntegrationService
from app.integration.policy_verification import PolicyVerification, policy_action_hash


def _canonical_hash(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class CoreV2PolicyAttestationVerifier:
    """In-process verifier for decisions emitted by the deterministic runtime.

    Only the bridge can register an exact full-action hash. Request fields that
    merely claim ``policy_engine`` authority are insufficient.
    """

    def __init__(self) -> None:
        self._attestations: dict[str, str] = {}

    def register(self, request: ExecutorServiceRequest, decision: PolicyV2Result) -> str:
        contextual_verified = (
            decision.mode == "contextual_v2"
            and decision.finding.provider_id == "deterministic_contextual_authorization"
            and decision.finding.evidence.get("deterministic_verifier") is True
        )
        legacy_verified = decision.mode == "legacy" and decision.finding.provider_id == "legacy_max_risk_threshold"
        if not (contextual_verified or legacy_verified):
            raise PermissionError("CORE_V2_POLICY_ATTESTATION_INVALID")
        action_hash = policy_action_hash(request)
        reference = f"guardx-policy-v2://attestations/{action_hash}"
        self._attestations[action_hash] = reference
        return reference

    def verify(self, request: ExecutorServiceRequest) -> PolicyVerification:
        if request.action_origin.authority != "policy_engine" or not request.action_origin.trusted:
            return PolicyVerification(False, None, "origin is not the deterministic policy runtime")
        action_hash = policy_action_hash(request)
        reference = self._attestations.get(action_hash)
        return PolicyVerification(bool(reference), reference, "exact Core-v2 action attestation lookup")


class CoreV2CapabilityVerifierAdapter:
    """Exact service-contract binding backed by the trusted CapabilityStore."""

    def __init__(self, capability_store: CapabilityStore) -> None:
        self.capability_store = capability_store
        self._bindings: dict[tuple[str, str, str, str], tuple[str, ContextualAuthorizationRequest]] = {}

    def register(
        self,
        *,
        session_id: str,
        tool: str,
        target: str,
        context: ContextualAuthorizationRequest,
        decision: PolicyV2Result,
    ) -> None:
        verification = self.capability_store.verify(context)
        finding_verification = decision.finding.evidence.get("capability_verification", {})
        key = (session_id, context.requested_capability, tool, target)
        finding_bound = decision.mode == "legacy" or (
            decision.finding.capability_granted
            and finding_verification.get("store_sha256") == self.capability_store.store_sha256
        )
        if not verification.granted or not verification.constraints_satisfied or not finding_bound or verification.grant is None:
            self._bindings.pop(key, None)
            return
        reference = f"capability-store://{self.capability_store.store_id}/{verification.grant.grant_id}"
        self._bindings[key] = (reference, context.model_copy(deep=True))

    def verify(self, *, session_id: str, capability: str, tool: str, target: str) -> CapabilityVerification:
        key = (session_id, capability, tool, target)
        binding = self._bindings.get(key)
        reference = None
        if binding is not None:
            candidate_reference, context = binding
            current = self.capability_store.verify(context)
            if current.granted and current.constraints_satisfied:
                reference = candidate_reference
            else:
                self._bindings.pop(key, None)
        return CapabilityVerification(
            bool(reference),
            reference,
            "exact Core-v2 capability binding matched" if reference else "no exact trusted-store binding",
        )


class CoreV2ExecutorContractBridge:
    """Canonical adapter from PolicyV2Result to guardx-executor-service-v1."""

    bridge_version = "guardx-nf-i1-core-v2-executor-bridge-v1"

    def __init__(
        self,
        service: ExecutorIntegrationService,
        policy_verifier: CoreV2PolicyAttestationVerifier,
        capability_verifier: CoreV2CapabilityVerifierAdapter,
    ) -> None:
        self.service = service
        self.policy_verifier = policy_verifier
        self.capability_verifier = capability_verifier

    def build_request(
        self,
        *,
        session_id: str,
        context: ContextualAuthorizationRequest,
        decision: PolicyV2Result,
        continuation: dict[str, Any],
        tool: str,
        target: str,
        arguments: dict[str, Any],
        approval_reference: str | None = None,
    ) -> ExecutorServiceRequest:
        constraints: dict[str, Any] = {}
        if decision.enforcement == "ALLOW_WITH_CONSTRAINTS":
            # The frozen executor accepts a strict subset of Core constraints.
            # Rebinding every normalized argument is a deterministic and more
            # restrictive projection than forwarding unsupported keys.
            constraints = {"argument_equals": dict(arguments)}
        evidence_context = {
            "bridge_version": self.bridge_version,
            "authorization_context_id": context.context_id,
            "authorization_finding_sha256": _canonical_hash(decision.finding.model_dump(mode="json")),
            "continuation": continuation,
            "capability_store_sha256": self.capability_verifier.capability_store.store_sha256,
        }
        request = ExecutorServiceRequest(
            session_id=session_id,
            authorization_decision=AuthorizationDecisionContract(
                decision=decision.enforcement,
                source_version=decision.schema_version,
                policy_reference="guardx-policy-v2://deterministic-runtime",
                constraints=constraints,
            ),
            capability=context.requested_capability,
            tool=tool,
            target=target,
            arguments=arguments,
            action_origin=ActionOrigin(
                authority="policy_engine",
                principal_id="deterministic_contextual_authorization",
                trusted=True,
                provenance_ref="guardx-policy-v2://trusted-rule-store",
            ),
            approval_reference=approval_reference,
            evidence_context=evidence_context,
        )
        self.policy_verifier.register(request, decision)
        self.capability_verifier.register(
            session_id=session_id,
            tool=tool,
            target=target,
            context=context,
            decision=decision,
        )
        return request

    def execute(self, request: ExecutorServiceRequest) -> dict[str, Any]:
        return self.service.execute(request).model_dump(mode="json")
