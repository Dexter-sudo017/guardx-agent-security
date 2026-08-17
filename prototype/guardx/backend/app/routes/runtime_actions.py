from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from app.contracts import ApprovalResumeEnvelope, PlannedActionEnvelope
from app.services.integrated_runtime import IntegratedRuntimeService, PlannerAuthorizationBindingError


router = APIRouter(prefix="/v1/runtime", tags=["contextual-runtime"])


def _service(request: Request) -> IntegratedRuntimeService:
    service = getattr(request.app.state, "integrated_runtime_service", None)
    if not isinstance(service, IntegratedRuntimeService):
        raise HTTPException(status_code=503, detail="integrated authorization runtime is not provisioned")
    return service


@router.post("/actions/execute")
def execute_planned_action(payload: PlannedActionEnvelope, request: Request) -> dict[str, Any]:
    try:
        return _service(request).execute_planned_action(payload)
    except PlannerAuthorizationBindingError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (PermissionError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/approvals/resume")
def resume_approved_action(payload: ApprovalResumeEnvelope, request: Request) -> dict[str, Any]:
    try:
        return _service(request).resume_approved_action(payload)
    except (KeyError, PermissionError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
