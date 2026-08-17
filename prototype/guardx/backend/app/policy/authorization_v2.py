from __future__ import annotations

from typing import Any

from app.capabilities import CapabilityStore, CapabilityVerification
from app.contracts import AuthorizationFinding, ContextualAuthorizationRequest, PolicyDecision, PolicyV2Result, RuleMatch
from app.policy.rule_retrieval import retrieve_rule_matches


UNTRUSTED_SOURCES = {
    "rag_document",
    "ocr_observation",
    "web_content",
    "tool_output",
    "external_message",
    "retrieved_context",
    "ocr",
    "vlm_observation",
}
NO_SIDE_EFFECT_CAPABILITIES = {"respond", "none"}
CONTROL_PLANE_CAPABILITIES = {"policy_change", "capability_grant"}
_RULE_EFFECT_ORDER = {
    None: 0,
    "ALLOW": 1,
    "ALLOW_WITH_CONSTRAINTS": 2,
    "QUARANTINE_AND_CONTINUE": 3,
    "REQUIRE_APPROVAL": 4,
    "DENY_ACTION": 5,
    "TERMINATE": 6,
}


def _source_authority(request: ContextualAuthorizationRequest) -> str:
    provenance = request.provenance
    provenance_source = provenance.source_type if provenance else request.source
    provenance_trust = provenance.trust if provenance else request.source_trust
    if request.source in UNTRUSTED_SOURCES or provenance_source in UNTRUSTED_SOURCES or provenance_trust == "untrusted":
        return "observation_only"
    if request.source in {"trusted_policy", "system", "developer"} and provenance_trust == "trusted":
        return "trusted_policy"
    if request.source in {"authenticated_user", "user"} and provenance_trust == "trusted":
        return "authorized_instruction"
    return "unknown"


def _data_flow(request: ContextualAuthorizationRequest, enforcement: str) -> str:
    allowed = enforcement in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}
    if request.sink in {"external", "unauthorized"}:
        return "authorized_external" if allowed else "blocked_external"
    if request.requested_capability in NO_SIDE_EFFECT_CAPABILITIES:
        return "none"
    return "authorized_local" if allowed else "blocked_local"


def _policy_decision(finding: AuthorizationFinding) -> PolicyDecision:
    constraints = {
        "policy_version": "CONTEXTUAL_V2",
        "authorization_decision": finding.decision,
        "source_authority": finding.source_authority,
        "requested_capability": finding.requested_capability,
        "capability_granted": finding.capability_granted,
        "matched_rules": finding.matched_rules,
        "rule_provenance": [item.provenance.model_dump(mode="json") for item in finding.rule_matches],
        "preserve_observation": finding.preserve_observation,
        "continue_original_task": finding.continue_original_task,
        "capability_constraints": finding.constraints,
    }
    required_guards = ["deterministic_contextual_authorization"]
    if finding.evidence.get("model_evidence_present"):
        required_guards.append(str(finding.evidence.get("model_provider_id") or "contextual_authorization_provider"))
    if finding.decision in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}:
        return PolicyDecision(
            route="allow",
            action="allow",
            risk_score=0.0,
            reasons=[f"policy_v2_{finding.decision.lower()}"],
            constraints=constraints,
            required_guards=required_guards,
            audit_level="summary" if finding.decision == "ALLOW" else "full",
        )
    if finding.decision == "REQUIRE_APPROVAL":
        return PolicyDecision(
            route="review",
            action="require_confirm",
            risk_score=0.5,
            reasons=["policy_v2_require_approval"],
            constraints=constraints,
            required_guards=required_guards,
            audit_level="full",
        )
    if finding.decision == "QUARANTINE_AND_CONTINUE":
        return PolicyDecision(
            route="review",
            action="rewrite",
            risk_score=0.7,
            reasons=["policy_v2_quarantine_action_continue_task"],
            constraints=constraints,
            required_guards=required_guards,
            audit_level="full",
        )
    risk_score = 1.0 if finding.decision == "TERMINATE" else 0.9
    return PolicyDecision(
        route="block",
        action="terminate",
        risk_score=risk_score,
        reasons=[f"policy_v2_{finding.decision.lower()}"],
        constraints=constraints,
        required_guards=required_guards,
        audit_level="full",
    )


def _strongest_rule_effect(matches: list[RuleMatch]) -> str | None:
    effects = [item.effect for item in matches if item.effect is not None]
    return max(effects, key=lambda item: _RULE_EFFECT_ORDER[item], default=None)


def _model_uncertainty(model_finding: AuthorizationFinding | None) -> list[str]:
    if model_finding is None:
        return []
    reasons = list(model_finding.uncertainty_reasons)
    if model_finding.evidence.get("provider_failure"):
        reasons.append("provider_failure")
    if model_finding.confidence < 0.6:
        reasons.append("low_model_confidence")
    return list(dict.fromkeys(reasons))


def _determine_enforcement(
    request: ContextualAuthorizationRequest,
    *,
    source_authority: str,
    verification: CapabilityVerification,
    task_alignment: bool,
    action_alignment: bool,
    rule_effect: str | None,
    model_finding: AuthorizationFinding | None,
    uncertainty: list[str],
) -> str:
    observation_side_effect = source_authority == "observation_only" and request.requested_capability not in NO_SIDE_EFFECT_CAPABILITIES

    # A trusted hard rule is evaluated before any semantic recommendation.
    if rule_effect == "TERMINATE":
        return "TERMINATE"
    if observation_side_effect:
        return "QUARANTINE_AND_CONTINUE"
    if request.requested_capability in CONTROL_PLANE_CAPABILITIES and source_authority != "trusted_policy":
        return "DENY_ACTION"
    if not verification.granted or not verification.constraints_satisfied:
        return "DENY_ACTION"
    if not task_alignment or not action_alignment:
        return "DENY_ACTION"
    if rule_effect == "DENY_ACTION":
        return "DENY_ACTION"
    if request.sink in {"external", "unauthorized"} and request.data_classification in {"private", "secret"}:
        return "DENY_ACTION"
    if rule_effect == "REQUIRE_APPROVAL" or request.approval_required:
        return "REQUIRE_APPROVAL"
    if uncertainty:
        return "REQUIRE_APPROVAL"

    # Model recommendations may restrict a deterministically valid action, but
    # never override trust, rule, approval, or capability verification.
    if model_finding is not None:
        if model_finding.decision == "TERMINATE":
            return "TERMINATE"
        if model_finding.decision == "DENY_ACTION":
            return "DENY_ACTION"
        if model_finding.decision == "QUARANTINE_AND_CONTINUE":
            return "QUARANTINE_AND_CONTINUE"
        if model_finding.decision == "REQUIRE_APPROVAL":
            return "REQUIRE_APPROVAL"
    if verification.grant and verification.grant.constraints:
        return "ALLOW_WITH_CONSTRAINTS"
    return "ALLOW"


def decide_contextual_authorization(
    request: ContextualAuthorizationRequest,
    *,
    capability_store: CapabilityStore | None = None,
    model_finding: AuthorizationFinding | None = None,
) -> PolicyV2Result:
    """Evaluate Policy v2 with a non-bypassable deterministic verification layer.

    Omitting the store is deliberately fail-safe: request/model capability claims
    are recorded but never treated as grants.
    """

    store = capability_store or CapabilityStore(store_id="missing_capability_store")
    verification = store.verify(request)
    rule_matches = retrieve_rule_matches(request)
    source_authority = _source_authority(request)
    trusted_authority = source_authority in {"authorized_instruction", "trusted_policy"}
    task_alignment = bool(request.task_alignment if request.task_alignment is not None else True)
    default_action_alignment = task_alignment and (
        trusted_authority or request.requested_capability in NO_SIDE_EFFECT_CAPABILITIES
    )
    action_alignment = bool(
        request.action_alignment if request.action_alignment is not None else default_action_alignment
    )
    uncertainty = _model_uncertainty(model_finding)
    enforcement = _determine_enforcement(
        request,
        source_authority=source_authority,
        verification=verification,
        task_alignment=task_alignment,
        action_alignment=action_alignment,
        rule_effect=_strongest_rule_effect(rule_matches),
        model_finding=model_finding,
        uncertainty=uncertainty,
    )
    preserve_observation = source_authority == "observation_only"
    continue_original_task = enforcement == "QUARANTINE_AND_CONTINUE" or (
        preserve_observation and enforcement not in {"TERMINATE"}
    )
    grant_constraints: dict[str, Any] = dict(verification.grant.constraints) if verification.grant else {}
    deterministic_rule_ids = [item.rule_id for item in rule_matches]
    model_rule_claims = list(model_finding.matched_rules) if model_finding else []
    model_claim_mismatches: list[str] = []
    if model_finding:
        if model_finding.requested_capability != request.requested_capability:
            model_claim_mismatches.append("requested_capability")
        if model_finding.capability_granted != verification.granted:
            model_claim_mismatches.append("capability_granted")
        if model_finding.source_authority != source_authority:
            model_claim_mismatches.append("source_authority")
        if set(model_rule_claims) - set(deterministic_rule_ids):
            model_claim_mismatches.append("matched_rules")

    finding = AuthorizationFinding(
        provider_id="deterministic_contextual_authorization",
        source_authority=source_authority,
        task_alignment=task_alignment,
        action_alignment=action_alignment,
        requested_capability=request.requested_capability,
        capability_granted=verification.granted,
        data_flow=_data_flow(request, enforcement),
        matched_rules=deterministic_rule_ids,
        rule_matches=rule_matches,
        decision=enforcement,
        preserve_observation=preserve_observation,
        continue_original_task=continue_original_task,
        confidence=model_finding.confidence if model_finding else 1.0,
        uncertainty_reasons=uncertainty,
        constraints=grant_constraints,
        model_version=model_finding.model_version if model_finding else "deterministic_policy_v2",
        evidence={
            "deterministic_verifier": True,
            "model_evidence_present": model_finding is not None,
            "model_provider_id": model_finding.provider_id if model_finding else None,
            "model_recommendation": model_finding.decision if model_finding else None,
            "model_capability_claim": model_finding.capability_granted if model_finding else None,
            "model_rule_claims": model_rule_claims,
            "ignored_model_claim_mismatches": model_claim_mismatches,
            "context_capability_claims": request.granted_capabilities,
            "capability_verification": verification.model_dump(mode="json"),
            "rule_store_verified": True,
        },
    )
    continuation = {
        "preserve_original_task": continue_original_task,
        "quarantined_action": enforcement == "QUARANTINE_AND_CONTINUE",
        "eligible": enforcement == "QUARANTINE_AND_CONTINUE",
        "hook_invoked": False,
    }
    return PolicyV2Result(
        finding=finding,
        policy_decision=_policy_decision(finding),
        enforcement=enforcement,
        review_required=enforcement == "REQUIRE_APPROVAL",
        continuation=continuation,
    )
