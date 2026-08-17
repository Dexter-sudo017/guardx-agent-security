from typing import Any

from pydantic import BaseModel, Field

from app.contracts import PolicyDecision, RiskFinding, RiskSegment
from app.observability import trace_id_from_metadata
from app.orchestration.observation_flow import resolve_output_policy
from app.policy import apply_policy_profile, effective_policy_risk_score, resolve_policy_profile
from app.risk_providers import RiskProviderRequest, guarded_risk_findings, legacy_action_for_policy, policy_decision_for_findings, score_registered_risk_providers


class GuardedPolicyAssembly(BaseModel):
    action: str
    risk_findings: list[RiskFinding] = Field(default_factory=list)
    provider_findings: list[RiskFinding] = Field(default_factory=list)
    policy_decision: PolicyDecision
    trace_events: list[dict[str, Any]] = Field(default_factory=list)
    output_redacted: bool = False


def prepare_guarded_policy(
    *,
    surface: str,
    total_risk: float,
    input_analysis: Any,
    embedding_analysis: Any | None = None,
    context_analysis: Any | None = None,
    segments: list[RiskSegment] | None = None,
    metadata: dict[str, Any] | None = None,
    session_id: str = "default-session",
) -> GuardedPolicyAssembly:
    provider_findings: list[RiskFinding] = []
    if segments:
        provider_findings = score_registered_risk_providers(
            RiskProviderRequest(
                request_id=trace_id_from_metadata(metadata, fallback=session_id),
                session_id=session_id,
                surface=surface,
                segments=segments,
                metadata=metadata or {},
            )
        )
    risk_findings = guarded_risk_findings(
        surface=surface,
        input_analysis=input_analysis,
        context_analysis=context_analysis,
        embedding_analysis=embedding_analysis,
        segments=segments,
        provider_findings=provider_findings,
    )
    profile = resolve_policy_profile(metadata)
    effective_risk = effective_policy_risk_score(total_risk, risk_findings, profile)
    policy_decision = apply_policy_profile(
        policy_decision_for_findings(effective_risk, risk_findings, thresholds=profile.thresholds),
        profile,
    )
    return GuardedPolicyAssembly(
        action=legacy_action_for_policy(policy_decision),
        risk_findings=risk_findings,
        provider_findings=provider_findings,
        policy_decision=policy_decision,
    )


def finalize_guarded_policy(
    *,
    surface: str,
    total_risk: float,
    current_action: str,
    policy_decision: PolicyDecision,
    input_analysis: Any,
    embedding_analysis: Any | None = None,
    context_analysis: Any | None = None,
    output_analysis: Any | None = None,
    segments: list[RiskSegment] | None = None,
    provider_findings: list[RiskFinding] | None = None,
    session_id: str,
    event_type: str,
    metadata: dict[str, Any] | None = None,
    output_threshold: float | None,
) -> GuardedPolicyAssembly:
    risk_findings = guarded_risk_findings(
        surface=surface,
        input_analysis=input_analysis,
        context_analysis=context_analysis,
        embedding_analysis=embedding_analysis,
        output_analysis=output_analysis,
        segments=segments,
        provider_findings=provider_findings,
    )
    output_policy = resolve_output_policy(
        risk_findings=risk_findings,
        policy_decision=policy_decision,
        session_id=session_id,
        event_type=event_type,
        metadata=metadata,
        output_threshold=output_threshold,
    )
    resolved_action = current_action
    if output_policy.output_redacted:
        resolved_action = legacy_action_for_policy(output_policy.policy_decision)
    return GuardedPolicyAssembly(
        action=resolved_action,
        risk_findings=output_policy.risk_findings,
        provider_findings=list(provider_findings or []),
        policy_decision=output_policy.policy_decision,
        trace_events=output_policy.trace_events,
        output_redacted=output_policy.output_redacted,
    )
