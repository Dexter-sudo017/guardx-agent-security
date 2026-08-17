from __future__ import annotations

from app.contracts import ExecutionLifecycleEvent, ExecutorCapability
from app.executor.runtime_models import ToolExecutionOutcome
from app.models import ToolDecision


def precheck_event(
    *,
    input_ref: str,
    decision: ToolDecision,
    review_error: str | None,
    precheck_latency_ms: float,
    runner_metadata: dict,
    capability: ExecutorCapability,
) -> ExecutionLifecycleEvent:
    return ExecutionLifecycleEvent(
        phase="precheck",
        status="failed" if review_error else ("success" if decision.allowed else "blocked"),
        input_ref=input_ref,
        output_ref="tool_decision",
        error=review_error or (None if decision.allowed else decision.reason),
        latency_ms=precheck_latency_ms,
        metadata={
            "mode": decision.mode,
            "allowed": decision.allowed,
            "rule_id": decision.rule_id,
            "evidence": decision.evidence,
            "constraints": decision.constraints,
            **runner_metadata,
            "capability": capability.model_dump(),
        },
    )


def blocked_events(*, execution_key: str, decision: ToolDecision, observation: str, runner_metadata: dict, capability: ExecutorCapability) -> list[ExecutionLifecycleEvent]:
    return [
        ExecutionLifecycleEvent(
            phase="execute",
            status="skipped",
            input_ref="tool_decision",
            error=decision.reason,
            metadata={"reason": "precheck_blocked", **runner_metadata, "capability": capability.model_dump()},
        ),
        ExecutionLifecycleEvent(
            phase="observe",
            status="blocked",
            input_ref="tool_decision",
            output_ref=f"{execution_key}:blocked_observation",
            error=decision.reason,
            metadata={"observation": observation},
        ),
        ExecutionLifecycleEvent(
            phase="rollback",
            status="skipped",
            input_ref=f"{execution_key}:blocked_observation",
            metadata={"reason": "no_side_effects_before_allow"},
        ),
    ]


def success_events(
    *,
    execution_key: str,
    outcome: ToolExecutionOutcome,
    execute_latency_ms: float,
    runner_metadata: dict,
    capability: ExecutorCapability,
) -> list[ExecutionLifecycleEvent]:
    return [
        ExecutionLifecycleEvent(
            phase="execute",
            status="success",
            input_ref="tool_decision",
            output_ref=outcome.output_ref,
            latency_ms=execute_latency_ms,
            metadata={**outcome.metadata, **runner_metadata, "capability": capability.model_dump()},
        ),
        ExecutionLifecycleEvent(
            phase="observe",
            status="success",
            input_ref=outcome.output_ref,
            output_ref=f"{execution_key}:observation",
            metadata={"observation": outcome.observation},
        ),
        ExecutionLifecycleEvent(
            phase="rollback",
            status="skipped",
            input_ref=f"{execution_key}:observation",
            metadata={"reason": "no_rollback_required"},
        ),
    ]


def append_execute_failure(
    *,
    events: list[ExecutionLifecycleEvent],
    execution_key: str,
    tool_name: str,
    error: str,
    execute_latency_ms: float,
    runner_metadata: dict,
    capability: ExecutorCapability,
    runtime_policy: dict | None = None,
    status: str = "failed",
    attempt: int = 1,
    retry_scheduled: bool = False,
    final_attempt: bool = True,
) -> None:
    events.append(
        ExecutionLifecycleEvent(
            phase="execute",
            status=status,
            input_ref="tool_decision",
            output_ref=f"{execution_key}:failed_execution",
            error=error,
            latency_ms=execute_latency_ms,
            metadata={
                "tool_name": tool_name,
                "attempt": attempt,
                "retry_scheduled": retry_scheduled,
                **runner_metadata,
                "capability": capability.model_dump(),
                "runtime_policy": runtime_policy or {},
            },
        )
    )
    if final_attempt:
        events.append(
            ExecutionLifecycleEvent(
                phase="observe",
                status="skipped",
                input_ref=f"{execution_key}:failed_execution",
                error=error,
                metadata={"reason": "execute_failed"},
            )
        )


def append_rollback_success(
    *,
    events: list[ExecutionLifecycleEvent],
    execution_key: str,
    rollback: ToolExecutionOutcome,
    rollback_latency_ms: float,
    capability: ExecutorCapability,
    runtime_policy: dict | None = None,
) -> None:
    events.append(
        ExecutionLifecycleEvent(
            phase="rollback",
            status="rolled_back",
            input_ref=f"{execution_key}:failed_execution",
            output_ref=rollback.output_ref,
            latency_ms=rollback_latency_ms,
            metadata={**rollback.metadata, "capability": capability.model_dump(), "runtime_policy": runtime_policy or {}},
        )
    )


def append_rollback_failure(*, events: list[ExecutionLifecycleEvent], execution_key: str, original_error: str, rollback_error: str, rollback_latency_ms: float) -> None:
    events.append(
        ExecutionLifecycleEvent(
            phase="rollback",
            status="failed",
            input_ref=f"{execution_key}:failed_execution",
            error=rollback_error,
            latency_ms=rollback_latency_ms,
            metadata={"original_error": original_error},
        )
    )


def append_rollback_skipped(*, events: list[ExecutionLifecycleEvent], execution_key: str, reason: str, runtime_policy: dict | None = None) -> None:
    events.append(
        ExecutionLifecycleEvent(
            phase="rollback",
            status="skipped",
            input_ref=f"{execution_key}:failed_execution",
            metadata={"reason": reason, "runtime_policy": runtime_policy or {}},
        )
    )
