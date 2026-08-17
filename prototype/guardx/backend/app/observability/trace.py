from typing import Any
from uuid import uuid4

from app.contracts import ExecutionPlan, ExecutionReport, ExperimentContext, PolicyDecision, RiskFinding, TraceEvent


def experiment_context_from_metadata(metadata: dict[str, Any] | None) -> ExperimentContext:
    metadata = metadata or {}
    plugin_versions = metadata.get("plugin_versions") if isinstance(metadata.get("plugin_versions"), dict) else {}
    thresholds = metadata.get("thresholds") if isinstance(metadata.get("thresholds"), dict) else {}
    seed = metadata.get("seed")
    try:
        seed_value = int(seed) if seed is not None else None
    except (TypeError, ValueError):
        seed_value = None
    return ExperimentContext(
        suite_id=str(metadata.get("suite_id")) if metadata.get("suite_id") is not None else None,
        case_id=str(metadata.get("case_id")) if metadata.get("case_id") is not None else None,
        policy_profile=str(metadata.get("policy_profile")) if metadata.get("policy_profile") is not None else None,
        plugin_versions={str(key): str(value) for key, value in plugin_versions.items()},
        thresholds={str(key): float(value) for key, value in thresholds.items()},
        seed=seed_value,
    )


def trace_id_from_metadata(metadata: dict[str, Any] | None, *, fallback: str | None = None) -> str:
    metadata = metadata or {}
    for key in ("trace_id", "replay_id", "request_id", "case_id"):
        value = metadata.get(key)
        if value is not None and str(value).strip():
            return str(value)
    return fallback or f"gx-trace-{uuid4().hex}"


def make_trace_event(
    *,
    trace_id: str,
    stage: str,
    payload_ref: str | None = None,
    risk_findings: list[RiskFinding] | None = None,
    policy_decision: PolicyDecision | None = None,
    execution_plan: ExecutionPlan | None = None,
    execution_report: ExecutionReport | None = None,
    metadata: dict[str, Any] | None = None,
    error: str | None = None,
    span_id: str | None = None,
) -> TraceEvent:
    risk_snapshot: dict[str, Any] = {}
    if risk_findings is not None:
        risk_snapshot["risk_findings"] = [finding.model_dump() for finding in risk_findings]
    if policy_decision is not None:
        risk_snapshot["policy_decision"] = policy_decision.model_dump()
    if execution_plan is not None:
        risk_snapshot["execution_plan"] = execution_plan.model_dump()
    if execution_report is not None:
        risk_snapshot["execution_report"] = execution_report.model_dump()
    return TraceEvent(
        trace_id=trace_id,
        span_id=span_id or f"{stage}-{uuid4().hex[:12]}",
        stage=stage,
        payload_ref=payload_ref,
        risk_snapshot=risk_snapshot,
        error=error,
        experiment=experiment_context_from_metadata(metadata),
    )


def trace_events_for_policy(
    *,
    trace_id: str,
    payload_ref: str,
    risk_findings: list[RiskFinding],
    policy_decision: PolicyDecision,
    metadata: dict[str, Any] | None = None,
    include_output: bool = False,
    include_executor: bool = False,
    execution_plan: ExecutionPlan | None = None,
    execution_report: ExecutionReport | None = None,
) -> list[dict[str, Any]]:
    events = [
        make_trace_event(
            trace_id=trace_id,
            stage="policy",
            payload_ref=payload_ref,
            risk_findings=risk_findings,
            policy_decision=policy_decision,
            metadata=metadata,
        ).model_dump()
    ]
    if include_executor or execution_plan is not None or execution_report is not None:
        events.append(
            make_trace_event(
                trace_id=trace_id,
                stage="executor",
                payload_ref=payload_ref,
                risk_findings=risk_findings,
                policy_decision=policy_decision,
                execution_plan=execution_plan,
                execution_report=execution_report,
                metadata=metadata,
            ).model_dump()
        )
    if include_output:
        events.append(
            make_trace_event(
                trace_id=trace_id,
                stage="output",
                payload_ref=payload_ref,
                risk_findings=risk_findings,
                policy_decision=policy_decision,
                metadata=metadata,
            ).model_dump()
        )
    return events

