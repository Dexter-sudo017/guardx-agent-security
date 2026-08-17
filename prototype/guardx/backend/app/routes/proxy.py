from typing import Any

from fastapi import APIRouter, Request

from app.audit.logger import log_proxy_result
from app.orchestration import run_anythingllm_proxy_flow, run_custom_rag_proxy_flow
from app.services.proxy_runtime import require_proxy_token
from app.services.runtime_state import audit_store

router = APIRouter()


@router.post("/v1/proxy/anythingllm/workspace/{workspace_slug}/chat")
async def proxy_anythingllm_workspace_chat(workspace_slug: str, raw_request: Request) -> dict[str, Any]:
    require_proxy_token(raw_request)
    result = run_anythingllm_proxy_flow(
        workspace_slug=workspace_slug,
        payload=await raw_request.json(),
        request_id=raw_request.headers.get("x-request-id"),
    )
    log_proxy_result(audit_store, flow="anythingllm", result=result)
    return result


@router.post("/v1/proxy/custom_rag/chat")
async def proxy_custom_rag_chat(raw_request: Request) -> dict[str, Any]:
    require_proxy_token(raw_request)
    result = run_custom_rag_proxy_flow(
        payload=await raw_request.json(),
        request_id=raw_request.headers.get("x-request-id"),
    )
    log_proxy_result(audit_store, flow="custom_rag", result=result)
    return result
