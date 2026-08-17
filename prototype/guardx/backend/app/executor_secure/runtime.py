from __future__ import annotations

from time import perf_counter
from typing import Any

from app.executor_secure.models import SecureExecutionResult
from app.executor_secure.permit import PermitAuthority, normalized_args_hash
from app.executor_secure.runner_base import SecureRunner
from app.executor_secure.trace_chain import TraceChain


def _ms(started: float) -> float:
    return round((perf_counter() - started) * 1000.0, 3)


class SecureExecutor:
    def __init__(self, authority: PermitAuthority) -> None:
        self.authority = authority

    def execute(self, *, execution_id: str, runner: SecureRunner, capability: str, args: dict[str, Any]) -> SecureExecutionResult:
        chain = TraceChain(execution_id)
        before_state = runner.state_hash()
        before_invocations = runner.invocation_count
        started = perf_counter()
        pre_started = perf_counter()
        decision = runner.normalize_and_precheck(args)
        if decision.allowed and not runner.capability_precheck(capability, decision.normalized_args):
            decision = type(decision)(False, "capability is not authorized for normalized operation", decision.normalized_args)
        precheck_ms = _ms(pre_started)
        args_hash = normalized_args_hash(decision.normalized_args)
        chain.append(
            "precheck",
            normalized_args_hash=args_hash,
            permit_hash=None,
            precheck_result="allow" if decision.allowed else "deny",
            runner_invoked=False,
            side_effect_observation=before_state,
            rollback_result=None,
            reason=decision.reason,
        )
        if not decision.allowed:
            after_state = runner.state_hash()
            result = SecureExecutionResult(
                execution_id, runner.runner_id, capability, "deny", False,
                runner.invocation_count - before_invocations, before_state, after_state,
                int(before_state != after_state), events=chain.events, trace_root_hash=chain.root_hash,
                timings_ms={"precheck": precheck_ms, "end_to_end": _ms(started)},
            )
            return result
        permit_started = perf_counter()
        permit = self.authority.issue(
            execution_id=execution_id,
            runner_id=runner.runner_id,
            capability=capability,
            args=decision.normalized_args,
        )
        permit_ms = _ms(permit_started)
        permit_hash = permit.public_hash()
        chain.append(
            "permit_issued",
            normalized_args_hash=args_hash,
            permit_hash=permit_hash,
            precheck_result="allow",
            runner_invoked=False,
            side_effect_observation=before_state,
            rollback_result=None,
        )
        runner_started = perf_counter()
        output: dict[str, Any] = {}
        error: str | None = None
        try:
            output = runner.run(
                execution_id=execution_id,
                capability=capability,
                args=decision.normalized_args,
                permit=permit,
            )
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
        runner_ms = _ms(runner_started)
        after_state = runner.state_hash()
        chain.append(
            "runner_result",
            normalized_args_hash=args_hash,
            permit_hash=permit_hash,
            precheck_result="allow",
            runner_invoked=True,
            side_effect_observation=after_state,
            rollback_result=None,
            error=error,
        )
        return SecureExecutionResult(
            execution_id, runner.runner_id, capability, "allow", True,
            runner.invocation_count - before_invocations, before_state, after_state,
            int(before_state != after_state), output=output, error=error,
            events=chain.events, trace_root_hash=chain.root_hash,
            timings_ms={"precheck": precheck_ms, "permit_issuance": permit_ms, "runner": runner_ms, "end_to_end": _ms(started)},
        )

    def rollback(self, result: SecureExecutionResult, runner: SecureRunner) -> SecureExecutionResult:
        started = perf_counter()
        rollback = runner.rollback(result.execution_id)
        after_state = runner.state_hash()
        chain = TraceChain(result.execution_id)
        chain.events = [dict(event) for event in result.events]
        chain.append(
            "rollback",
            normalized_args_hash=result.events[0]["normalized_args_hash"],
            permit_hash=result.events[-1].get("permit_hash"),
            precheck_result=result.precheck_result,
            runner_invoked=False,
            side_effect_observation=after_state,
            rollback_result=rollback,
        )
        result.rollback = rollback
        result.after_state = after_state
        result.events = chain.events
        result.trace_root_hash = chain.root_hash
        result.timings_ms["rollback"] = _ms(started)
        result.timings_ms["end_to_end"] = round(result.timings_ms.get("end_to_end", 0.0) + result.timings_ms["rollback"], 3)
        return result
