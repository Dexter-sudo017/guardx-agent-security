from typing import Any

from app.contracts.audit import ExperimentReportResponse


def _top(mapping: dict[str, int]) -> dict[str, Any]:
    if not mapping:
        return {"name": "none", "count": 0}
    name, count = max(mapping.items(), key=lambda item: item[1])
    return {"name": name, "count": count}


def _provider_counts(summary: dict[str, Any]) -> dict[str, int]:
    providers = summary.get("risk_providers", {}).get("by_provider", {})
    return {provider_id: int(bucket.get("total", 0)) for provider_id, bucket in providers.items()}


def _profile_counts(summary: dict[str, Any]) -> dict[str, int]:
    profiles = summary.get("policy_profiles", {}).get("by_profile", {})
    return {profile: int(bucket.get("total", 0)) for profile, bucket in profiles.items()}


def _findings(summary: dict[str, Any]) -> list[dict[str, Any]]:
    quality = summary.get("run_quality", {})
    executor = summary.get("executor_policy_summary", {})
    findings = []
    if not quality.get("comparison_ready"):
        findings.append({"severity": "warning", "category": "reproducibility", "message": "Experiment metadata is incomplete.", "evidence": quality.get("missing", {})})
    failure_reasons = executor.get("failure_reasons", {})
    top_failure = _top({key: value for key, value in failure_reasons.items() if key != "none"})
    if top_failure["count"]:
        findings.append({"severity": "warning", "category": "executor_policy", "message": "Executor failures are present in this run.", "evidence": top_failure})
    top_provider = _top(_provider_counts(summary))
    if top_provider["count"]:
        findings.append({"severity": "info", "category": "risk_provider", "message": "Risk findings are concentrated by provider.", "evidence": top_provider})
    return findings


def _recommendations(summary: dict[str, Any], findings: list[dict[str, Any]]) -> list[str]:
    categories = {item["category"] for item in findings}
    recommendations = []
    if "reproducibility" in categories:
        recommendations.append("Normalize suite_id, case_id, policy_profile, and trace_id before comparing experiment slices.")
    if "executor_policy" in categories:
        recommendations.append("Inspect executor timeout, retry, and rollback policy buckets before changing tool behavior.")
    if "risk_provider" in categories:
        recommendations.append("Review the top provider's risk types and evidence before tuning thresholds.")
    if not recommendations and summary.get("run_quality", {}).get("comparison_ready"):
        recommendations.append("This slice is ready for policy-profile comparison.")
    return recommendations


def _markdown(report: dict[str, Any]) -> str:
    metrics = report["key_metrics"]
    return "\n".join(
        [
            "# GuardX Experiment Run Report",
            f"- Fingerprint: {report['run_fingerprint']}",
            f"- Comparison ready: {report['comparison_ready']}",
            f"- Decision records: {metrics['decision_records']}",
            f"- Risk findings: {metrics['risk_findings']}",
            f"- Executor executions: {metrics['executor_executions']}",
            f"- Top policy profile: {metrics['top_policy_profile']['name']}",
            f"- Top risk provider: {metrics['top_risk_provider']['name']}",
            "",
            "## Recommended Next Actions",
            *[f"- {item}" for item in report["recommended_next_actions"]],
        ]
    )


def build_experiment_report(summary_response: dict[str, Any]) -> dict[str, Any]:
    summary = summary_response.get("summary", {})
    quality = summary.get("run_quality", {})
    findings = _findings(summary)
    report = {
        "scope": {key: summary_response.get(key) for key in ("session_id", "trace_id", "filters")},
        "run_fingerprint": quality.get("run_fingerprint", "0" * 16),
        "comparison_ready": bool(quality.get("comparison_ready")),
        "key_metrics": {
            "decision_records": int(summary.get("total_decision_records", 0)),
            "risk_findings": int(summary.get("risk_providers", {}).get("total_findings", 0)),
            "executor_executions": int(summary.get("executor_policy_summary", {}).get("total_executions", 0)),
            "policy_profiles": _profile_counts(summary),
            "risk_providers": _provider_counts(summary),
            "top_policy_profile": _top(_profile_counts(summary)),
            "top_risk_provider": _top(_provider_counts(summary)),
        },
        "findings": findings,
        "recommended_next_actions": _recommendations(summary, findings),
    }
    report["markdown"] = _markdown(report)
    return ExperimentReportResponse(**report).model_dump()
