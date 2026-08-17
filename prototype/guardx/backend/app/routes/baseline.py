from typing import Any

from fastapi import APIRouter

from app.audit.logger import log_baseline_result
from app.models import GuardedChatRequest, GuardedRagRequest, ToolCallRequest
from app.orchestration import run_baseline_chat_route_flow, run_baseline_rag_route_flow, run_baseline_tool_route_flow
from app.services.runtime_state import audit_store

router = APIRouter()


@router.post("/v1/baseline/chat")
def baseline_chat(request: GuardedChatRequest) -> dict[str, Any]:
    payload = run_baseline_chat_route_flow(request)
    log_baseline_result(audit_store, flow="chat", result=payload)
    return payload


@router.post("/v1/baseline/rag_chat")
def baseline_rag_chat(request: GuardedRagRequest) -> dict[str, Any]:
    payload = run_baseline_rag_route_flow(request)
    log_baseline_result(audit_store, flow="rag", result=payload)
    return payload


@router.post("/v1/baseline/tool_call")
def baseline_tool_call(request: ToolCallRequest) -> dict[str, Any]:
    payload = run_baseline_tool_route_flow(request)
    log_baseline_result(audit_store, flow="tool_call", result=payload)
    return payload
