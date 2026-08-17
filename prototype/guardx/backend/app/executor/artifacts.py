import hashlib
import json
from typing import Any

from app.contracts import ExecutionPlan, ExecutionReport, PlanStep, StepResult, TrustBoundary
from app.models import ToolDecision


def bounded_risk(value: float | int | str | None) -> float:
    try:
        score = float(value if value is not None else 0.0)
    except (TypeError, ValueError):
        score = 0.0
    return min(1.0, max(0.0, score))


def execution_key(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True, default=str).encode("utf-8")
    return f"gx-exec-{hashlib.sha256(encoded).hexdigest()[:24]}"


def execution_plan(
    *,
    execution_key: str,
    session_id: str,
    surface: str,
    tool_name: str,
    risk_score: float,
    replay_id: str,
) -> ExecutionPlan:
    return ExecutionPlan(
        plan_id=execution_key,
        planner_id="guardx_executor_pipeline",
        steps=[
            PlanStep(
                step_id="pre_action_review",
                capability=tool_name,
                input_ref=f"{session_id}:{surface}:{replay_id or 'live'}",
                constraints={
                    "risk_score": risk_score,
                    "execution_mode": "pre_execution_review",
                    "rollback_policy": "no_side_effects_before_allow",
                },
                rollback={},
                trust_boundary=TrustBoundary(
                    source="agent_action",
                    trust_level="bounded",
                    executable=True,
                    can_instruct_model=False,
                ),
            )
        ],
        risk_hints=[f"session_risk={risk_score:.6f}"],
        assumptions=["Tool calls are reviewed before sandbox execution."],
    )


def execution_report(
    *,
    execution_key: str,
    tool_name: str,
    decision: ToolDecision,
    latency_ms: float,
    error: str | None = None,
) -> ExecutionReport:
    if error:
        status = "failed"
    elif decision.allowed:
        status = "success"
    else:
        status = "blocked"
    return ExecutionReport(
        plan_id=execution_key,
        status=status,
        step_results=[
            StepResult(
                step_id="pre_action_review",
                status=status,
                output_ref=tool_name,
                error=error or (None if decision.allowed else decision.reason),
                latency_ms=latency_ms,
            )
        ],
        errors=[item for item in [error, None if decision.allowed else decision.reason] if item],
        rollback_results=[],
    )
