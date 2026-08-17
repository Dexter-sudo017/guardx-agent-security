from typing import Any

from app.audit.experiment_records import decision_policy_profile, decision_record, experiment_metadata


def has_experiment_filters(*, suite_id: str | None, case_id: str | None, policy_profile: str | None) -> bool:
    return bool(suite_id or case_id or policy_profile)


def experiment_filter_payload(*, suite_id: str | None, case_id: str | None, policy_profile: str | None) -> dict[str, Any]:
    return {
        "suite_id": suite_id,
        "case_id": case_id,
        "policy_profile": policy_profile,
    }


def _matches(record: dict[str, Any], *, suite_id: str | None, case_id: str | None, policy_profile: str | None) -> bool:
    experiment = experiment_metadata(record)
    if suite_id and str(experiment.get("suite_id")) != suite_id:
        return False
    if case_id and str(experiment.get("case_id")) != case_id:
        return False
    if policy_profile and decision_policy_profile(record) != policy_profile:
        return False
    return True


def filter_experiment_decision_records(
    decision_records: list[dict[str, Any]],
    *,
    suite_id: str | None = None,
    case_id: str | None = None,
    policy_profile: str | None = None,
) -> list[dict[str, Any]]:
    if not has_experiment_filters(suite_id=suite_id, case_id=case_id, policy_profile=policy_profile):
        return decision_records
    return [
        row
        for row in decision_records
        if _matches(decision_record(row), suite_id=suite_id, case_id=case_id, policy_profile=policy_profile)
    ]


def filter_experiment_executions(
    executions: list[dict[str, Any]],
    decision_records: list[dict[str, Any]],
    *,
    filters_active: bool,
) -> list[dict[str, Any]]:
    if not filters_active:
        return executions
    trace_ids = {str(record.get("trace_id")) for row in decision_records if (record := decision_record(row)).get("trace_id")}
    if not trace_ids:
        return []
    return [execution for execution in executions if str(execution.get("trace_id")) in trace_ids]
