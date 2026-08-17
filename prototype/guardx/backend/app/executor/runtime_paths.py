from __future__ import annotations

from app.contracts import ExecutionLifecycleEvent, ExecutionLifecycleReport, ExecutorCapability
from app.executor.runtime_events import blocked_events, success_events
from app.executor.runtime_models import ExecutorLifecycleRun, ToolExecutionOutcome
from app.models import ToolDecision


def blocked_path_run(
    *,
    execution_key: str,
    decision: ToolDecision,
    events: list[ExecutionLifecycleEvent],
    runner_metadata: dict,
    capability: ExecutorCapability,
    precheck_latency_ms: float,
    total_latency_ms: float,
    review_error: str | None,
) -> ExecutorLifecycleRun:
    observation = f"GuardX blocked this action before sandbox execution: {decision.reason}"
    events.extend(blocked_events(execution_key=execution_key, decision=decision, observation=observation, runner_metadata=runner_metadata, capability=capability))
    return ExecutorLifecycleRun(
        decision=decision,
        lifecycle_report=ExecutionLifecycleReport(
            execution_key=execution_key,
            status="failed" if review_error else "blocked",
            events=events,
            rollback_required=False,
            rollback_completed=False,
        ),
        observation=observation,
        precheck_latency_ms=precheck_latency_ms,
        total_latency_ms=total_latency_ms,
        review_error=review_error,
    )


def success_path_run(
    *,
    execution_key: str,
    decision: ToolDecision,
    events: list[ExecutionLifecycleEvent],
    outcome: ToolExecutionOutcome,
    execute_latency_ms: float,
    runner_metadata: dict,
    capability: ExecutorCapability,
    precheck_latency_ms: float,
    total_latency_ms: float,
) -> ExecutorLifecycleRun:
    events.extend(
        success_events(
            execution_key=execution_key,
            outcome=outcome,
            execute_latency_ms=execute_latency_ms,
            runner_metadata=runner_metadata,
            capability=capability,
        )
    )
    return ExecutorLifecycleRun(
        decision=decision,
        lifecycle_report=ExecutionLifecycleReport(execution_key=execution_key, status="success", events=events),
        observation=outcome.observation,
        precheck_latency_ms=precheck_latency_ms,
        total_latency_ms=total_latency_ms,
        review_error=None,
    )


def failed_path_run(
    *,
    execution_key: str,
    decision: ToolDecision,
    events: list[ExecutionLifecycleEvent],
    error: str,
    precheck_latency_ms: float,
    total_latency_ms: float,
    rollback_completed: bool,
    status: str = "failed",
    rollback_required: bool = True,
) -> ExecutorLifecycleRun:
    return ExecutorLifecycleRun(
        decision=decision,
        lifecycle_report=ExecutionLifecycleReport(
            execution_key=execution_key,
            status=status,
            events=events,
            rollback_required=rollback_required,
            rollback_completed=rollback_completed,
        ),
        observation=f"GuardX executor failed during action execution: {error}",
        precheck_latency_ms=precheck_latency_ms,
        total_latency_ms=total_latency_ms,
        execution_error=error,
    )
