from typing import Any

from fastapi import APIRouter

from app.services.runtime_state import audit_store

router = APIRouter()


@router.post("/v1/audit/rebuild_indexes")
def rebuild_audit_indexes(session_id: str | None = None, limit: int | None = None) -> dict[str, Any]:
    return audit_store.rebuild_indexes(session_id=session_id, limit=limit)
