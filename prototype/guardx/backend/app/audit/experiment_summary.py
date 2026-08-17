from typing import Any

from app.audit.executor_policy_summary import summarize_executor_runtime_policy
from app.audit.experiment_matrix import summarize_experiment_matrix
from app.audit.experiment_quality import summarize_experiment_quality
from app.audit.experiment_records import decision_policy_profile, decision_record, experiment_metadata
from app.contracts.audit import ExperimentRunSummary


def _increment(mapping: dict[str, int], key: Any) -> None:
    normalized = str(key or "unknown")
    mapping[normalized] = mapping.get(normalized, 0) + 1


def _risk_stats(bucket: dict[str, Any], score: Any) -> None:
    value = float(score or 0.0)
    bucket["risk_score_total"] += value
    bucket["max_risk_score"] = max(bucket["max_risk_score"], value)
    bucket["avg_risk_score"] = bucket["risk_score_total"] / bucket["total"] if bucket["total"] else 0.0


def summarize_policy_profiles(decision_records: list[dict[str, Any]]) -> dict[str, Any]:
    by_profile: dict[str, dict[str, Any]] = {}
    for row in decision_records:
        record = decision_record(row)
        if not record:
            continue
        decision = record.get("policy_decision") if isinstance(record.get("policy_decision"), dict) else {}
        experiment = experiment_metadata(record)
        profile = decision_policy_profile(record)
        bucket = by_profile.setdefault(
            profile,
            {
                "total": 0,
                "routes": {},
                "actions": {},
                "audit_levels": {},
                "surfaces": {},
                "suites": {},
                "risk_score_total": 0.0,
                "avg_risk_score": 0.0,
                "max_risk_score": 0.0,
            },
        )
        bucket["total"] += 1
        _increment(bucket["routes"], decision.get("route"))
        _increment(bucket["actions"], decision.get("action"))
        _increment(bucket["audit_levels"], decision.get("audit_level"))
        _increment(bucket["surfaces"], record.get("surface"))
        _increment(bucket["suites"], experiment.get("suite_id"))
        _risk_stats(bucket, decision.get("risk_score"))
    return {"total_profiles": len(by_profile), "by_profile": by_profile}


def summarize_experiment_dimensions(decision_records: list[dict[str, Any]]) -> dict[str, Any]:
    dimensions = {"suites": {}, "cases": {}, "profiles": {}, "seeds": {}}
    for row in decision_records:
        record = decision_record(row)
        if not record:
            continue
        experiment = experiment_metadata(record)
        _increment(dimensions["suites"], experiment.get("suite_id"))
        _increment(dimensions["cases"], experiment.get("case_id"))
        _increment(dimensions["profiles"], decision_policy_profile(record))
        _increment(dimensions["seeds"], experiment.get("seed"))
    return dimensions


def summarize_risk_providers(decision_records: list[dict[str, Any]]) -> dict[str, Any]:
    by_provider: dict[str, dict[str, Any]] = {}
    total_findings = 0
    for row in decision_records:
        record = decision_record(row)
        findings = record.get("risk_findings") if isinstance(record.get("risk_findings"), list) else []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            total_findings += 1
            provider_id = str(finding.get("provider_id") or "unknown")
            bucket = by_provider.setdefault(
                provider_id,
                {
                    "total": 0,
                    "risk_types": {},
                    "severities": {},
                    "surfaces": {},
                    "risk_score_total": 0.0,
                    "avg_risk_score": 0.0,
                    "max_risk_score": 0.0,
                    "avg_latency_ms": 0.0,
                    "latency_ms_total": 0.0,
                    "model_versions": {},
                },
            )
            bucket["total"] += 1
            _increment(bucket["risk_types"], finding.get("risk_type"))
            _increment(bucket["severities"], finding.get("severity"))
            _increment(bucket["surfaces"], finding.get("surface"))
            _increment(bucket["model_versions"], finding.get("model_version"))
            _risk_stats(bucket, finding.get("risk_score"))
            latency = float(finding.get("latency_ms") or 0.0)
            bucket["latency_ms_total"] += latency
            bucket["avg_latency_ms"] = bucket["latency_ms_total"] / bucket["total"] if bucket["total"] else 0.0
    return {"total_findings": total_findings, "total_providers": len(by_provider), "by_provider": by_provider}


def summarize_experiment_run(
    *,
    decision_records: list[dict[str, Any]],
    executor_executions: list[dict[str, Any]],
) -> dict[str, Any]:
    summary = ExperimentRunSummary(
        total_decision_records=len(decision_records),
        run_quality=summarize_experiment_quality(decision_records, executor_executions),
        experiment_dimensions=summarize_experiment_dimensions(decision_records),
        comparison_matrix=summarize_experiment_matrix(decision_records, executor_executions),
        policy_profiles=summarize_policy_profiles(decision_records),
        risk_providers=summarize_risk_providers(decision_records),
        executor_policy_summary=summarize_executor_runtime_policy(executor_executions),
    )
    return summary.model_dump()
