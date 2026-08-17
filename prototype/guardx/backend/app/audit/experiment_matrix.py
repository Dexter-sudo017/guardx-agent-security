import json
from typing import Any

from app.audit.experiment_records import decision_policy_profile, decision_record


def _increment(mapping: dict[str, int], key: Any) -> None:
    normalized = str(key or "unknown")
    mapping[normalized] = mapping.get(normalized, 0) + 1


def _risk_stats(bucket: dict[str, Any], score: Any) -> None:
    value = float(score or 0.0)
    bucket["risk_score_total"] += value
    bucket["max_risk_score"] = max(bucket["max_risk_score"], value)
    bucket["avg_risk_score"] = bucket["risk_score_total"] / bucket["total"] if bucket["total"] else 0.0


def _runtime_policy_key(policy: dict[str, Any]) -> str:
    return json.dumps(policy, sort_keys=True, ensure_ascii=False) if policy else "unknown"


def _trace_profiles(decision_records: list[dict[str, Any]]) -> dict[str, str]:
    profiles = {}
    for row in decision_records:
        record = decision_record(row)
        trace_id = record.get("trace_id")
        if trace_id:
            profiles[str(trace_id)] = decision_policy_profile(record)
    return profiles


def _provider_matrix(decision_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matrix: dict[tuple[str, str], dict[str, Any]] = {}
    for row in decision_records:
        record = decision_record(row)
        profile = decision_policy_profile(record)
        findings = record.get("risk_findings") if isinstance(record.get("risk_findings"), list) else []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            provider_id = str(finding.get("provider_id") or "unknown")
            bucket = matrix.setdefault(
                (profile, provider_id),
                {
                    "policy_profile": profile,
                    "provider_id": provider_id,
                    "total": 0,
                    "risk_types": {},
                    "severities": {},
                    "risk_score_total": 0.0,
                    "avg_risk_score": 0.0,
                    "max_risk_score": 0.0,
                },
            )
            bucket["total"] += 1
            _increment(bucket["risk_types"], finding.get("risk_type"))
            _increment(bucket["severities"], finding.get("severity"))
            _risk_stats(bucket, finding.get("risk_score"))
    return [matrix[key] for key in sorted(matrix)]


def _executor_matrix(decision_records: list[dict[str, Any]], executor_executions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    profiles = _trace_profiles(decision_records)
    matrix: dict[tuple[str, str], dict[str, Any]] = {}
    for execution in executor_executions:
        policy = execution.get("runtime_policy") if isinstance(execution.get("runtime_policy"), dict) else {}
        profile = profiles.get(str(execution.get("trace_id")), "unknown")
        policy_key = _runtime_policy_key(policy)
        bucket = matrix.setdefault(
            (profile, policy_key),
            {
                "policy_profile": profile,
                "runtime_policy_key": policy_key,
                "runtime_policy": policy,
                "total": 0,
                "statuses": {},
                "tools": {},
                "runners": {},
            },
        )
        bucket["total"] += 1
        _increment(bucket["statuses"], execution.get("status"))
        _increment(bucket["tools"], execution.get("capability", {}).get("tool_name"))
        _increment(bucket["runners"], execution.get("runner_id"))
    return [matrix[key] for key in sorted(matrix)]


def summarize_experiment_matrix(
    decision_records: list[dict[str, Any]],
    executor_executions: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "profile_provider": _provider_matrix(decision_records),
        "profile_executor": _executor_matrix(decision_records, executor_executions),
    }
