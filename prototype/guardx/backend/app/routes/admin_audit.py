from typing import Any

from fastapi import APIRouter

from app.services.runtime_state import audit_store

router = APIRouter()


@router.get("/v1/audit/sessions/{session_id}")
def get_session_audit(session_id: str, limit: int = 20) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "events": audit_store.recent_by_session(session_id=session_id, limit=limit),
    }


@router.get("/v1/audit/recent")
def get_recent_audit(limit: int = 100, event_type: str | None = None) -> dict[str, Any]:
    return {"events": audit_store.recent(limit=limit, event_type=event_type)}


@router.get("/v1/audit/traces")
def get_audit_traces(session_id: str | None = None, trace_id: str | None = None, limit: int = 100) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "trace_id": trace_id,
        "events": audit_store.trace_events(session_id=session_id, trace_id=trace_id, limit=limit),
    }


@router.get("/v1/audit/traces/{trace_id}")
def get_audit_trace(trace_id: str, session_id: str | None = None, limit: int = 100) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "trace_id": trace_id,
        "events": audit_store.trace_events(session_id=session_id, trace_id=trace_id, limit=limit),
    }


@router.get("/v1/audit/decision_records")
def get_decision_records(session_id: str | None = None, request_id: str | None = None, trace_id: str | None = None, limit: int = 100) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "request_id": request_id,
        "trace_id": trace_id,
        "events": audit_store.decision_records(session_id=session_id, request_id=request_id, trace_id=trace_id, limit=limit),
    }


@router.get("/v1/audit/decision_records/{request_id}")
def get_decision_record(request_id: str, session_id: str | None = None, limit: int = 100) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "request_id": request_id,
        "events": audit_store.decision_records(session_id=session_id, request_id=request_id, limit=limit),
    }
