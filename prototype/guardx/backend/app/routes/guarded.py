from typing import Any

from fastapi import APIRouter, Request

from app.audit.logger import log_guarded_response, log_guarded_tool_result
from app.models import GuardedChatRequest, GuardedRagDemoRequest, GuardedRagFileRequest, GuardedRagRequest, GuardedResponse, GuardedVlmImageRequest, GuardedVlmOcrRequest, ToolCallRequest
from app.orchestration import run_guarded_chat_flow, run_guarded_rag_flow, run_guarded_tool_call, run_guarded_vlm_flow
from app.services.guarded_runtime import adapter_registry, audit_store, session_risk_state
from app.services.live_rag import retrieve_qdrant_bge
from app.services.live_vlm_ocr import analyze_image_with_registered_vlm as analyze_image_with_local_vlm
from app.services.rag_live_demo import run_rag_demo, run_rag_files
from app.services.vlm_live_demo import run_vlm_image

router = APIRouter()


def _run_and_log(flow, request):
    result = flow(request)
    log_guarded_response(audit_store, flow=result.flow, response=result.response, trace_events=result.trace_events, decision_record=result.decision_record)
    return result.response


@router.post("/v1/guarded/chat", response_model=GuardedResponse)
def guarded_chat(request: GuardedChatRequest) -> GuardedResponse:
    return _run_and_log(run_guarded_chat_flow, request)


@router.post("/v1/guarded/rag_chat", response_model=GuardedResponse)
def guarded_rag_chat(request: GuardedRagRequest) -> GuardedResponse:
    return _run_and_log(run_guarded_rag_flow, request)


@router.post("/v1/guarded/vlm_ocr_chat", response_model=GuardedResponse)
def guarded_vlm_ocr_chat(request: GuardedVlmOcrRequest) -> GuardedResponse:
    return _run_and_log(run_guarded_vlm_flow, request)


@router.post("/v1/guarded/rag_demo_query")
def guarded_rag_demo_query(request: GuardedRagDemoRequest, raw_request: Request) -> dict[str, Any]:
    return run_rag_demo(request, raw_request, retrieve=retrieve_qdrant_bge, rag_flow=run_guarded_rag_flow)


@router.post("/v1/guarded/rag_file_query")
def guarded_rag_file_query(request: GuardedRagFileRequest, raw_request: Request) -> dict[str, Any]:
    return run_rag_files(request, raw_request, retrieve=retrieve_qdrant_bge, rag_flow=run_guarded_rag_flow)


@router.post("/v1/guarded/vlm_image_analyze")
def guarded_vlm_image_analyze(request: GuardedVlmImageRequest, raw_request: Request) -> dict[str, Any]:
    return run_vlm_image(request, raw_request, analyze_image=analyze_image_with_local_vlm, registry=adapter_registry, vlm_flow=run_guarded_vlm_flow)


@router.post("/v1/guarded/tool_call")
def guarded_tool_call(request: ToolCallRequest) -> dict[str, Any]:
    payload = run_guarded_tool_call(session_id=request.session_id, tool_name=request.tool_name, args=request.args, risk_hint=request.risk_hint, base_risk=session_risk_state[request.session_id], surface="agent_tool")
    log_guarded_tool_result(audit_store, result=payload)
    return payload
