from typing import Any

from fastapi import APIRouter

from app.audit.executor_policy_summary import summarize_executor_runtime_policy
from app.audit.executor_replay_service import load_executor_replay
from app.audit.experiment_service import build_experiment_summary_response
from app.services.plugin_session_replay import build_plugin_session_replay
from app.services.runtime_state import audit_store

router = APIRouter()


def _executor_replay(session_id: str | None = None, trace_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    return load_executor_replay(audit_store, session_id=session_id, trace_id=trace_id, limit=limit)


@router.get("/v1/audit/executor_replay")
def get_executor_replay(session_id: str | None = None, trace_id: str | None = None, limit: int = 200) -> dict[str, Any]:
    executions = _executor_replay(session_id=session_id, trace_id=trace_id, limit=limit)
    return {
        "session_id": session_id,
        "trace_id": trace_id,
        "executions": executions,
    }


@router.get("/v1/audit/executor_replay/{trace_id}")
def get_executor_replay_by_trace(trace_id: str, session_id: str | None = None, limit: int = 200) -> dict[str, Any]:
    return get_executor_replay(session_id=session_id, trace_id=trace_id, limit=limit)


@router.get("/v1/audit/plugin_session_replay")
def get_plugin_session_replay(
    session_id: str | None = None,
    trace_id: str | None = None,
    limit: int = 2000,
) -> dict[str, Any]:
    records = audit_store.decision_records(session_id=session_id, trace_id=trace_id, limit=limit)
    executions = _executor_replay(session_id=session_id, trace_id=trace_id, limit=limit)
    return build_plugin_session_replay(records, executions, session_id=session_id, trace_id=trace_id)


@router.get("/v1/audit/executor_policy_summary")
def get_executor_policy_summary(session_id: str | None = None, trace_id: str | None = None, limit: int = 500) -> dict[str, Any]:
    executions = _executor_replay(session_id=session_id, trace_id=trace_id, limit=limit)
    return {
        "session_id": session_id,
        "trace_id": trace_id,
        "summary": summarize_executor_runtime_policy(executions),
    }


@router.post("/v1/audit/seed_demo_replay")
def post_seed_demo_replay(session_id: str | None = None, model: str = "mock-safe-model", limit: int = 2000) -> dict[str, Any]:
    from scripts.seed_guardx_audit_replay import seed_audit_replay

    return seed_audit_replay(session_id=session_id, model=model, limit=limit)


@router.get("/v1/audit/experiment_summary")
def get_experiment_summary(
    session_id: str | None = None,
    trace_id: str | None = None,
    suite_id: str | None = None,
    case_id: str | None = None,
    policy_profile: str | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    records = audit_store.decision_records(session_id=session_id, trace_id=trace_id, limit=limit)
    executions = _executor_replay(session_id=session_id, trace_id=trace_id, limit=limit)
    return build_experiment_summary_response(
        session_id=session_id,
        trace_id=trace_id,
        suite_id=suite_id,
        case_id=case_id,
        policy_profile=policy_profile,
        decision_records=records,
        executor_executions=executions,
    )
