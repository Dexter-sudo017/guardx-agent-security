from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.contracts.executor_integration import ApprovalDecisionRequest, ApprovalInspectResponse, ApprovalValidationResponse, ExecutorServiceRequest, ExecutorServiceResponse, RollbackRequest, SessionExecutionTraceResponse
from app.integration.api_binding import configure_executor_integration, executor_service


router = APIRouter(prefix="/v1/executor", tags=["executor-integration"])


@router.post("/executions", response_model=ExecutorServiceResponse)
def post_execution(body: ExecutorServiceRequest, request: Request) -> ExecutorServiceResponse:
    return executor_service(request).execute(body)


@router.get("/executions/{execution_id}", response_model=ExecutorServiceResponse)
def get_execution_status(execution_id: str, request: Request) -> ExecutorServiceResponse:
    try:
        return executor_service(request).status(execution_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/executions/{execution_id}/rollback", response_model=ExecutorServiceResponse)
def post_execution_rollback(execution_id: str, body: RollbackRequest, request: Request) -> ExecutorServiceResponse:
    del body  # Reason is an operator audit field; the frozen runner rollback semantics stay unchanged.
    try:
        return executor_service(request).rollback(execution_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="execution is not rollback-capable") from exc


@router.post("/approvals/{approval_id}/approve", response_model=ApprovalInspectResponse)
def post_approval_approve(approval_id: str, body: ApprovalDecisionRequest, request: Request) -> ApprovalInspectResponse:
    del body  # UI supplies intent only; server-side signer supplies identity and grant.
    try:
        return executor_service(request).approve(approval_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (PermissionError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/approvals/{approval_id}/reject", response_model=ApprovalInspectResponse)
def post_approval_reject(approval_id: str, body: ApprovalDecisionRequest, request: Request) -> ApprovalInspectResponse:
    del body
    try:
        return executor_service(request).reject(approval_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (PermissionError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/approvals/{approval_id}", response_model=ApprovalInspectResponse)
def get_approval(approval_id: str, request: Request) -> ApprovalInspectResponse:
    try:
        return executor_service(request).inspect_approval(approval_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/approvals/{approval_id}/validate", response_model=ApprovalValidationResponse)
def get_approval_validation(approval_id: str, request: Request) -> ApprovalValidationResponse:
    try:
        return executor_service(request).validate_approval(approval_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/sessions/{session_id}/trace", response_model=SessionExecutionTraceResponse)
def get_execution_session_trace(session_id: str, request: Request) -> SessionExecutionTraceResponse:
    return executor_service(request).session_trace(session_id)
