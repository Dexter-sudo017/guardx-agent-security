from typing import Any


def _policy_key(policy: dict[str, Any]) -> str:
    return "|".join(
        [
            f"timeout={policy.get('execution_timeout_ms', '')}",
            f"retries={policy.get('max_retries', '')}",
            f"backoff={policy.get('retry_backoff_ms', '')}",
            f"rollback={policy.get('rollback_on_failure', '')}",
            f"rollback_timeout={policy.get('rollback_timeout_ms', '')}",
        ]
    )


def _failure_reason(execution: dict[str, Any]) -> str:
    for phase in execution.get("phases", []):
        status = phase.get("status")
        if status in {"failed", "timeout", "blocked"}:
            return f"{phase.get('phase')}:{status}:{phase.get('error') or phase.get('metadata', {}).get('reason', '')}"
    return "none"


def _new_bucket(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "policy": policy,
        "total": 0,
        "statuses": {},
        "failure_reasons": {},
        "rollback": {"required": 0, "completed": 0, "skipped": 0},
        "tools": {},
        "runners": {},
    }


def _increment(mapping: dict[str, int], key: Any) -> None:
    normalized = str(key)
    mapping[normalized] = mapping.get(normalized, 0) + 1


def summarize_executor_runtime_policy(executions: list[dict[str, Any]]) -> dict[str, Any]:
    buckets: dict[str, dict[str, Any]] = {}
    by_status: dict[str, int] = {}
    failure_reasons: dict[str, int] = {}
    for execution in executions:
        policy = execution.get("runtime_policy") if isinstance(execution.get("runtime_policy"), dict) else {}
        bucket = buckets.setdefault(_policy_key(policy), _new_bucket(policy))
        status = execution.get("status", "unknown")
        reason = _failure_reason(execution)
        tool_name = execution.get("capability", {}).get("tool_name", "unknown")
        runner_id = execution.get("runner_id", "unknown")
        bucket["total"] += 1
        _increment(bucket["statuses"], status)
        _increment(bucket["failure_reasons"], reason)
        _increment(bucket["tools"], tool_name)
        _increment(bucket["runners"], runner_id)
        _increment(by_status, status)
        _increment(failure_reasons, reason)
        phases = execution.get("phases", [])
        rollback_phase = next((phase for phase in phases if phase.get("phase") == "rollback"), {})
        if rollback_phase.get("status") == "rolled_back":
            bucket["rollback"]["completed"] += 1
        elif rollback_phase.get("status") == "skipped":
            bucket["rollback"]["skipped"] += 1
        if execution.get("status") in {"failed", "timeout"} and policy.get("rollback_on_failure"):
            bucket["rollback"]["required"] += 1
    return {
        "schema_version": "guardx-executor-runtime-policy-summary-v1",
        "total_executions": len(executions),
        "by_status": by_status,
        "failure_reasons": failure_reasons,
        "policy_buckets": [
            {"key": key, **bucket}
            for key, bucket in sorted(buckets.items(), key=lambda item: item[0])
        ],
    }
