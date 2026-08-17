from typing import Any

from app.executor import review_tool_request
from app.observability import tool_execution_trace_metadata, trace_events_for_executor_lifecycle, trace_events_for_policy, trace_id_from_metadata
from app.services.defense_orchestrator import build_defense_actions, defense_trace_event


def run_guarded_tool_call(
    *,
    session_id: str,
    tool_name: str,
    args: dict[str, Any],
    risk_hint: float | None,
    base_risk: float,
    surface: str = "agent_tool",
) -> dict[str, Any]:
    risk = risk_hint if risk_hint is not None else base_risk
    execution = review_tool_request(
        session_id=session_id,
        tool_name=tool_name,
        args=args,
        risk_score=risk,
        surface=surface,
    )
    trace_metadata = tool_execution_trace_metadata(surface=surface, execution_key=execution.execution_key)
    trace_id = trace_id_from_metadata(trace_metadata, fallback=session_id)
    payload_ref = f"{session_id}:guarded_tool_call"
    trace_events = trace_events_for_policy(
        trace_id=trace_id,
        payload_ref=payload_ref,
        risk_findings=execution.risk_findings,
        policy_decision=execution.policy_decision,
        metadata=trace_metadata,
        include_executor=True,
        execution_plan=execution.execution_plan,
        execution_report=execution.execution_report,
    )
    trace_events.extend(
        trace_events_for_executor_lifecycle(
            trace_id=trace_id,
            payload_ref=payload_ref,
            lifecycle_report=execution.lifecycle_report,
            metadata=trace_metadata,
        )
    )
    defense_actions = build_defense_actions(
        flow="tool",
        policy_decision=execution.policy_decision,
        risk_findings=execution.risk_findings,
        trust_boundary="agent_tool_capability_boundary",
        execution_report=execution.execution_report,
    )
    if defense_actions:
        trace_events.append(
            defense_trace_event(
                trace_id=trace_id,
                payload_ref=payload_ref,
                defense_actions=defense_actions,
                metadata=trace_metadata,
            )
        )
    return {
        "session_id": session_id,
        "execution_key": execution.execution_key,
        "tool_name": execution.tool_name,
        "args": args,
        "mapped_args": execution.mapped_args,
        "risk": execution.risk_score,
        "decision": execution.decision.model_dump(),
        "risk_findings": [item.model_dump() for item in execution.risk_findings],
        "policy_decision": execution.policy_decision.model_dump(),
        "execution_plan": execution.execution_plan.model_dump(),
        "execution_report": execution.execution_report.model_dump(),
        "lifecycle_report": execution.lifecycle_report.model_dump(),
        "defense_actions": defense_actions,
        "trace_events": trace_events,
    }
