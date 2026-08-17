from typing import Any

from fastapi import APIRouter

from app.audit.executor_replay_service import load_executor_replay
from app.services.runtime_state import audit_store
from app.services.ocr_evidence_summary import build_ocr_evidence_summary
from app.services.security_log_insights import build_security_log_insights
from app.services.sequence_audit import build_api_sequence_audit
from app.services.supply_chain_audit import build_supply_chain_audit

router = APIRouter()


@router.get("/v1/audit/security_log_insights")
def get_security_log_insights(session_id: str | None = None, trace_id: str | None = None, limit: int = 500) -> dict[str, Any]:
    return build_security_log_insights(audit_store, session_id=session_id, trace_id=trace_id, limit=limit)


@router.get("/v1/audit/api_sequence_audit")
def get_api_sequence_audit(session_id: str | None = None, trace_id: str | None = None, limit: int = 500) -> dict[str, Any]:
    executions = load_executor_replay(audit_store, session_id=session_id, trace_id=trace_id, limit=limit)
    return build_api_sequence_audit(executions, session_id=session_id, trace_id=trace_id)


@router.get("/v1/runtime/supply_chain_audit")
def get_supply_chain_audit(session_id: str | None = None, trace_id: str | None = None, limit: int = 2000) -> dict[str, Any]:
    decision_records = audit_store.decision_records(session_id=session_id, trace_id=trace_id, limit=limit)
    return build_supply_chain_audit(decision_records)


@router.get("/v1/audit/ocr_evidence_summary")
def get_ocr_evidence_summary() -> dict[str, Any]:
    return build_ocr_evidence_summary()
