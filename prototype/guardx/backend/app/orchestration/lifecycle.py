from typing import Any

from app.contracts import (
    ExecutionLifecycleReport,
    ExecutionPlan,
    ExecutionReport,
    GuardedDecisionRecord,
    GuardedRuntimeEnvelope,
    PolicyDecision,
    RiskFinding,
    RiskSegment,
    TraceEvent,
)
from app.observability import experiment_context_from_metadata, trace_id_from_metadata


def build_runtime_envelope(
    *,
    session_id: str,
    flow: str,
    surface: str,
    segments: list[RiskSegment],
    model: str | None = None,
    request_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> GuardedRuntimeEnvelope:
    metadata = metadata or {}
    return GuardedRuntimeEnvelope(
        request_id=request_id or trace_id_from_metadata(metadata, fallback=session_id),
        session_id=session_id,
        flow=flow,
        surface=surface,
        model=model,
        segments=segments,
        metadata=metadata,
        experiment=experiment_context_from_metadata(metadata),
    )


def build_decision_record(
    *,
    envelope: GuardedRuntimeEnvelope,
    policy_decision: PolicyDecision,
    risk_findings: list[RiskFinding],
    trace_events: list[dict[str, Any]] | list[TraceEvent],
    stage: str = "policy",
    execution_plan: ExecutionPlan | None = None,
    execution_report: ExecutionReport | None = None,
    lifecycle_report: ExecutionLifecycleReport | None = None,
    trace_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> GuardedDecisionRecord:
    normalized_events = [item if isinstance(item, TraceEvent) else TraceEvent.model_validate(item) for item in trace_events]
    return GuardedDecisionRecord(
        request_id=envelope.request_id,
        trace_id=trace_id or trace_id_from_metadata(envelope.metadata, fallback=envelope.request_id),
        stage=stage,
        surface=envelope.surface,
        envelope=envelope,
        risk_findings=risk_findings,
        policy_decision=policy_decision,
        execution_plan=execution_plan,
        execution_report=execution_report,
        lifecycle_report=lifecycle_report,
        trace_events=normalized_events,
        metadata={**envelope.metadata, **(metadata or {})},
    )
