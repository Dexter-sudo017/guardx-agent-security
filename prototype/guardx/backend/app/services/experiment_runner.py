from uuid import uuid4

from app.audit.executor_replay_service import load_executor_replay
from app.audit.experiment_report import build_experiment_report
from app.audit.experiment_service import build_experiment_summary_response
from app.contracts.audit import ExperimentSuiteRunResponse
from app.services.experiment_case_runner import run_config_case
from app.services.experiment_suite_registry import experiment_suite_cases
from app.services.experiment_suite_registry import load_experiment_suites
from app.services.runtime_state import audit_store


def run_builtin_experiment_suite(
    *,
    suite_id: str = "guardx_builtin_smoke",
    policy_profile: str = "v5l",
    session_id: str | None = None,
    model: str = "mock-safe-model",
    seed: int = 77,
) -> dict:
    run_session = session_id or f"{suite_id}-{uuid4().hex[:8]}"
    manifest = load_experiment_suites()
    suite = manifest.suites.get(suite_id) or manifest.suites.get(manifest.default_suite)
    isolate_cases = bool(suite and suite.isolate_cases)
    cases = [
        run_config_case(
            session_id=f"{run_session}-{case.case_id}" if isolate_cases else run_session,
            suite_id=suite_id,
            policy_profile=policy_profile,
            seed=seed,
            index=index,
            model=model,
            case=case,
        )
        for index, case in enumerate(experiment_suite_cases(suite_id))
    ]
    records = audit_store.decision_records(session_id=run_session, limit=100)
    executions = load_executor_replay(audit_store, session_id=run_session, limit=100)
    summary_response = build_experiment_summary_response(
        session_id=run_session,
        trace_id=None,
        suite_id=suite_id,
        case_id=None,
        policy_profile=policy_profile,
        decision_records=records,
        executor_executions=executions,
    )
    report = build_experiment_report(summary_response)
    return ExperimentSuiteRunResponse(suite_id=suite_id, session_id=run_session, policy_profile=policy_profile, model=model, cases=cases, report=report).model_dump()
