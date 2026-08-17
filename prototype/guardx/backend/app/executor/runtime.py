from __future__ import annotations

from time import perf_counter
from typing import Any

from app.contracts import ExecutorCapability, ExecutorRuntimePolicy
from app.executor.capability_registry import capability_for
from app.executor.runner_registry import runner_for
from app.executor.runtime_models import ExecutorLifecycleRun, PrecheckFn, ToolRunner
from app.executor.runtime_attempts import run_execution_attempts
from app.executor.runtime_events import (
    append_rollback_failure,
    append_rollback_skipped,
    append_rollback_success,
    precheck_event,
)
from app.executor.runtime_policy import runtime_policy_for
from app.executor.timed_call import call_with_timeout
from app.executor.runtime_paths import (
    blocked_path_run,
    failed_path_run,
    success_path_run,
)
from app.models import ToolDecision
from app.sandbox.tools import review_tool_call


def _elapsed_ms(started: float) -> float:
    return round((perf_counter() - started) * 1000.0, 3)


def _precheck(
    *,
    tool_name: str,
    mapped_args: dict[str, Any],
    risk_score: float,
    precheck: PrecheckFn,
) -> tuple[ToolDecision, float, str | None]:
    started = perf_counter()
    try:
        decision = precheck(tool_name, mapped_args, risk_score)
        return decision, _elapsed_ms(started), None
    except Exception as exc:
        error = str(exc)
        decision = ToolDecision(
            allowed=False,
            reason=f"Executor review failed: {error}",
            mode="deny",
            sanitized_args={},
            rule_id="executor.precheck_error",
            evidence=[error],
        )
        return decision, _elapsed_ms(started), error


def run_executor_lifecycle(
    *,
    execution_key: str,
    session_id: str,
    surface: str,
    tool_name: str,
    mapped_args: dict[str, Any],
    risk_score: float,
    precheck: PrecheckFn = review_tool_call,
    runner: ToolRunner | None = None,
    capability: ExecutorCapability | None = None,
    runtime_policy: ExecutorRuntimePolicy | None = None,
) -> ExecutorLifecycleRun:
    total_started = perf_counter()
    active_capability = capability or capability_for(tool_name)
    active_policy = runtime_policy or runtime_policy_for(tool_name)
    runner_selection = runner_for(active_capability)
    active_runner = runner or runner_selection.runner
    runtime_policy_metadata = active_policy.model_dump()
    runner_metadata = {
        "runner_id": "injected_runner" if runner else runner_selection.runner_id,
        "runner_fallback_used": False if runner else runner_selection.fallback_used,
        "runtime_policy": runtime_policy_metadata,
    }
    input_ref = f"{session_id}:{surface}:{tool_name}"
    decision, precheck_latency_ms, review_error = _precheck(
        tool_name=tool_name,
        mapped_args=mapped_args,
        risk_score=risk_score,
        precheck=precheck,
    )
    events = [
        precheck_event(
            input_ref=input_ref,
            decision=decision,
            review_error=review_error,
            precheck_latency_ms=precheck_latency_ms,
            runner_metadata=runner_metadata,
            capability=active_capability,
        )
    ]
    if not decision.allowed:
        return blocked_path_run(
            execution_key=execution_key,
            decision=decision,
            events=events,
            runner_metadata=runner_metadata,
            capability=active_capability,
            precheck_latency_ms=precheck_latency_ms,
            total_latency_ms=_elapsed_ms(total_started),
            review_error=review_error,
        )

    execution_args = decision.sanitized_args or mapped_args
    attempts = run_execution_attempts(
        runner=active_runner,
        events=events,
        execution_key=execution_key,
        tool_name=tool_name,
        args=execution_args,
        runner_metadata=runner_metadata,
        capability=active_capability,
        runtime_policy=active_policy,
    )
    if attempts.outcome is not None:
        return success_path_run(
            execution_key=execution_key,
            decision=decision,
            events=events,
            outcome=attempts.outcome,
            execute_latency_ms=attempts.execute_latency_ms,
            runner_metadata=runner_metadata,
            capability=active_capability,
            precheck_latency_ms=precheck_latency_ms,
            total_latency_ms=_elapsed_ms(total_started),
        )

    rollback_completed = False
    rollback_required = active_policy.rollback_on_failure
    if active_policy.rollback_on_failure:
        rollback_started = perf_counter()
        try:
            rollback = call_with_timeout(
                lambda: active_runner.rollback(execution_key=execution_key, tool_name=tool_name, args=execution_args, error=attempts.error),
                timeout_ms=active_policy.rollback_timeout_ms,
                phase="rollback",
            )
            rollback_completed = True
            append_rollback_success(
                events=events,
                execution_key=execution_key,
                rollback=rollback,
                rollback_latency_ms=_elapsed_ms(rollback_started),
                capability=active_capability,
                runtime_policy=runtime_policy_metadata,
            )
        except Exception as rollback_exc:
            append_rollback_failure(
                events=events,
                execution_key=execution_key,
                original_error=attempts.error,
                rollback_error=str(rollback_exc),
                rollback_latency_ms=_elapsed_ms(rollback_started),
            )
    else:
        append_rollback_skipped(
            events=events,
            execution_key=execution_key,
            reason="rollback_disabled_by_runtime_policy",
            runtime_policy=runtime_policy_metadata,
        )
    return failed_path_run(
        execution_key=execution_key,
        decision=decision,
        events=events,
        error=attempts.error,
        precheck_latency_ms=precheck_latency_ms,
        total_latency_ms=_elapsed_ms(total_started),
        rollback_completed=rollback_completed,
        status="timeout" if attempts.status == "timeout" else "failed",
        rollback_required=rollback_required,
    )
