from typing import Any

from fastapi import APIRouter

from app.audit.executor_replay_service import load_executor_replay
from app.audit.experiment_report import build_experiment_report
from app.audit.experiment_service import build_experiment_summary_response
from app.services.experiment_artifact_index import current_model_recommendation_gate, list_experiment_artifacts
from app.services.experiment_model_matrix import run_model_matrix
from app.services.experiment_real_model_plan import DEFAULT_REAL_MODEL_SUITES, build_real_model_matrix_plan, split_csv
from app.services.experiment_runner import run_builtin_experiment_suite
from app.services.runtime_state import audit_store

router = APIRouter()


@router.get("/v1/audit/experiment_report")
def get_experiment_report(
    session_id: str | None = None,
    trace_id: str | None = None,
    suite_id: str | None = None,
    case_id: str | None = None,
    policy_profile: str | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    records = audit_store.decision_records(session_id=session_id, trace_id=trace_id, limit=limit)
    executions = load_executor_replay(audit_store, session_id=session_id, trace_id=trace_id, limit=limit)
    summary_response = build_experiment_summary_response(
        session_id=session_id,
        trace_id=trace_id,
        suite_id=suite_id,
        case_id=case_id,
        policy_profile=policy_profile,
        decision_records=records,
        executor_executions=executions,
    )
    return build_experiment_report(summary_response)


@router.get("/v1/audit/experiment_artifacts")
def get_experiment_artifacts(limit: int = 50, kind: str | None = None) -> dict[str, Any]:
    return list_experiment_artifacts(limit=limit, kind=kind)


@router.get("/v1/audit/model_recommendation_gate")
def get_model_recommendation_gate() -> dict[str, Any]:
    return current_model_recommendation_gate()


@router.get("/v1/audit/real_model_matrix_plan")
def get_real_model_matrix_plan(
    models: str = "auto",
    suites: str = ",".join(DEFAULT_REAL_MODEL_SUITES),
    profile: str = "v5l",
    include_local: bool = False,
    run_id: str = "admin-preflight",
) -> dict[str, Any]:
    return build_real_model_matrix_plan(run_id=run_id, raw_models=models, suites=split_csv(suites), profile=profile, include_local=include_local)


@router.post("/v1/audit/run_builtin_experiment")
def run_builtin_experiment(
    suite_id: str = "guardx_builtin_smoke",
    policy_profile: str = "v5l",
    session_id: str | None = None,
    model: str = "mock-safe-model",
    seed: int = 77,
) -> dict[str, Any]:
    return run_builtin_experiment_suite(suite_id=suite_id, policy_profile=policy_profile, session_id=session_id, model=model, seed=seed)


@router.post("/v1/audit/run_model_matrix")
def run_experiment_model_matrix(
    suite_id: str = "guardx_redteam_core",
    policy_profile: str = "v21",
    models: str = "mock-safe-model",
    base_session_id: str | None = None,
    seed: int = 77,
) -> dict[str, Any]:
    return run_model_matrix(suite_id=suite_id, policy_profile=policy_profile, models=models.split(","), base_session_id=base_session_id, seed=seed)
