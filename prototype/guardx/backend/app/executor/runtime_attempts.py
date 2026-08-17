from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter, sleep
from typing import Any

from app.contracts import ExecutionLifecycleEvent, ExecutorCapability, ExecutorRuntimePolicy
from app.executor.runtime_events import append_execute_failure
from app.executor.runtime_models import ToolExecutionOutcome, ToolRunner
from app.executor.timed_call import PhaseTimedOut, call_with_timeout


@dataclass(frozen=True)
class ExecutionAttemptsResult:
    outcome: ToolExecutionOutcome | None
    error: str
    status: str
    execute_latency_ms: float


def _elapsed_ms(started: float) -> float:
    return round((perf_counter() - started) * 1000.0, 3)


def run_execution_attempts(
    *,
    runner: ToolRunner,
    events: list[ExecutionLifecycleEvent],
    execution_key: str,
    tool_name: str,
    args: dict[str, Any],
    runner_metadata: dict,
    capability: ExecutorCapability,
    runtime_policy: ExecutorRuntimePolicy,
) -> ExecutionAttemptsResult:
    last_error = ""
    last_status = "failed"
    execute_latency_ms = 0.0
    max_attempts = runtime_policy.max_retries + 1
    policy_snapshot = runtime_policy.model_dump()
    for attempt_index in range(max_attempts):
        execute_started = perf_counter()
        retry_scheduled = attempt_index < max_attempts - 1
        try:
            outcome = call_with_timeout(
                lambda: runner.run(execution_key=execution_key, tool_name=tool_name, args=args),
                timeout_ms=runtime_policy.execution_timeout_ms,
                phase="execute",
            )
            return ExecutionAttemptsResult(
                outcome=outcome,
                error="",
                status="success",
                execute_latency_ms=_elapsed_ms(execute_started),
            )
        except PhaseTimedOut as exc:
            last_error = str(exc)
            last_status = "timeout"
        except Exception as exc:
            last_error = str(exc)
            last_status = "failed"
        execute_latency_ms = _elapsed_ms(execute_started)
        append_execute_failure(
            events=events,
            execution_key=execution_key,
            tool_name=tool_name,
            error=last_error,
            execute_latency_ms=execute_latency_ms,
            runner_metadata=runner_metadata,
            capability=capability,
            runtime_policy=policy_snapshot,
            status=last_status,
            attempt=attempt_index + 1,
            retry_scheduled=retry_scheduled,
            final_attempt=not retry_scheduled,
        )
        if retry_scheduled and runtime_policy.retry_backoff_ms > 0:
            sleep(runtime_policy.retry_backoff_ms / 1000.0)
    return ExecutionAttemptsResult(outcome=None, error=last_error, status=last_status, execute_latency_ms=execute_latency_ms)
