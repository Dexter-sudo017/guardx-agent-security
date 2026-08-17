import hashlib
import json
from typing import Any

from app.audit.experiment_records import decision_policy_profile, decision_record, experiment_metadata


def _fingerprint_payload(decision_records: list[dict[str, Any]], executor_executions: list[dict[str, Any]]) -> dict[str, Any]:
    records = []
    for row in decision_records:
        record = decision_record(row)
        experiment = experiment_metadata(record)
        records.append(
            {
                "request_id": record.get("request_id"),
                "trace_id": record.get("trace_id"),
                "surface": record.get("surface"),
                "suite_id": experiment.get("suite_id"),
                "case_id": experiment.get("case_id"),
                "policy_profile": decision_policy_profile(record),
                "seed": experiment.get("seed"),
            }
        )
    executions = [
        {
            "execution_key": item.get("execution_key"),
            "trace_id": item.get("trace_id"),
            "status": item.get("status"),
            "runtime_policy": item.get("runtime_policy", {}),
        }
        for item in executor_executions
    ]
    return {"records": sorted(records, key=lambda item: str(item)), "executions": sorted(executions, key=lambda item: str(item))}


def _missing_metadata_counts(decision_records: list[dict[str, Any]]) -> dict[str, int]:
    missing = {"suite_id": 0, "case_id": 0, "policy_profile": 0, "trace_id": 0, "risk_findings": 0}
    for row in decision_records:
        record = decision_record(row)
        experiment = experiment_metadata(record)
        if not experiment.get("suite_id"):
            missing["suite_id"] += 1
        if not experiment.get("case_id"):
            missing["case_id"] += 1
        if decision_policy_profile(record) == "unknown":
            missing["policy_profile"] += 1
        if not record.get("trace_id"):
            missing["trace_id"] += 1
        if not record.get("risk_findings"):
            missing["risk_findings"] += 1
    return missing


def summarize_experiment_quality(
    decision_records: list[dict[str, Any]],
    executor_executions: list[dict[str, Any]],
) -> dict[str, Any]:
    payload = _fingerprint_payload(decision_records, executor_executions)
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    missing = _missing_metadata_counts(decision_records)
    executions_without_policy = sum(1 for item in executor_executions if not item.get("runtime_policy"))
    return {
        "run_fingerprint": digest[:16],
        "comparison_ready": bool(decision_records) and not any(missing[key] for key in ("suite_id", "case_id", "policy_profile", "trace_id")),
        "coverage": {
            "decision_records": len(decision_records),
            "executor_executions": len(executor_executions),
            "executions_without_runtime_policy": executions_without_policy,
        },
        "missing": missing,
    }
