from typing import Any

from pydantic import BaseModel, Field

from app.contracts import PolicyDecision, RiskFinding
from app.observability import trace_events_for_policy, trace_id_from_metadata
from app.policy import apply_policy_profile, effective_policy_risk_score, resolve_policy_profile
from app.risk_providers import observation_risk_finding, output_override_policy_decision, policy_decision_for_findings


class ObservationPolicyAssembly(BaseModel):
    risk_findings: list[RiskFinding] = Field(default_factory=list)
    policy_decision: PolicyDecision
    trace_events: list[dict[str, Any]] = Field(default_factory=list)
    output_redacted: bool = False
    safe_to_return: bool = True
    mode: str = "allow"
    latency_ms: float = 0.0


def resolve_output_policy(
    *,
    risk_findings: list[RiskFinding],
    policy_decision: PolicyDecision,
    session_id: str,
    event_type: str,
    metadata: dict[str, Any] | None = None,
    output_threshold: float | None,
    fallback_trace_id: str | None = None,
    include_output_trace: bool = True,
    latency_ms: float = 0.0,
) -> ObservationPolicyAssembly:
    resolved_policy = policy_decision
    profile = resolve_policy_profile(metadata)
    active_output_threshold = profile.thresholds.medium if output_threshold is None else output_threshold
    output_finding = next((item for item in risk_findings if item.provider_id == "output_guard"), None)
    if output_finding is not None:
        resolved_policy = output_override_policy_decision(
            resolved_policy,
            output_finding,
            threshold=active_output_threshold,
        )
    output_redacted = resolved_policy.action == "redact"
    trace_events = trace_events_for_policy(
        trace_id=trace_id_from_metadata(metadata, fallback=fallback_trace_id or session_id),
        payload_ref=f"{session_id}:{event_type}",
        risk_findings=risk_findings,
        policy_decision=resolved_policy,
        metadata=metadata,
        include_output=include_output_trace,
    )
    return ObservationPolicyAssembly(
        risk_findings=risk_findings,
        policy_decision=resolved_policy,
        trace_events=trace_events,
        output_redacted=output_redacted,
        safe_to_return=not output_redacted,
        mode="redact_output" if output_redacted else "allow",
        latency_ms=latency_ms,
    )


def observe_output_analysis(
    *,
    surface: str,
    output_analysis: Any,
    session_id: str,
    event_type: str,
    metadata: dict[str, Any] | None = None,
    output_threshold: float | None,
    fallback_trace_id: str | None = None,
    latency_ms: float = 0.0,
) -> ObservationPolicyAssembly:
    risk_findings = [
        observation_risk_finding(
            surface=surface,
            analysis=output_analysis,
            latency_ms=latency_ms,
        )
    ]
    profile = resolve_policy_profile(metadata)
    policy_decision = apply_policy_profile(
        policy_decision_for_findings(
            effective_policy_risk_score(output_analysis.risk_score, risk_findings, profile),
            risk_findings,
            thresholds=profile.thresholds,
        ),
        profile,
    )
    return resolve_output_policy(
        risk_findings=risk_findings,
        policy_decision=policy_decision,
        session_id=session_id,
        event_type=event_type,
        metadata=metadata,
        output_threshold=output_threshold,
        fallback_trace_id=fallback_trace_id,
        latency_ms=latency_ms,
    )
