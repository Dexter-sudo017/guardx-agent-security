from typing import Any

from app.audit.experiment_filters import (
    experiment_filter_payload,
    filter_experiment_decision_records,
    filter_experiment_executions,
    has_experiment_filters,
)
from app.audit.experiment_summary import summarize_experiment_run
from app.contracts.audit import ExperimentSummaryResponse


def build_experiment_summary_response(
    *,
    session_id: str | None,
    trace_id: str | None,
    suite_id: str | None,
    case_id: str | None,
    policy_profile: str | None,
    decision_records: list[dict[str, Any]],
    executor_executions: list[dict[str, Any]],
) -> dict[str, Any]:
    filtered_records = filter_experiment_decision_records(
        decision_records,
        suite_id=suite_id,
        case_id=case_id,
        policy_profile=policy_profile,
    )
    filtered_executions = filter_experiment_executions(
        executor_executions,
        filtered_records,
        filters_active=has_experiment_filters(suite_id=suite_id, case_id=case_id, policy_profile=policy_profile),
    )
    response = ExperimentSummaryResponse(
        session_id=session_id,
        trace_id=trace_id,
        filters=experiment_filter_payload(suite_id=suite_id, case_id=case_id, policy_profile=policy_profile),
        summary=summarize_experiment_run(decision_records=filtered_records, executor_executions=filtered_executions),
    )
    return response.model_dump()
