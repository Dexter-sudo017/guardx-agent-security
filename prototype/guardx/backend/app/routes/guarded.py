from typing import Any

from fastapi import APIRouter, HTTPException, Request

from app.audit.logger import log_guarded_response, log_guarded_tool_result
from app.models import GuardedChatRequest, GuardedRagDemoRequest, GuardedRagRequest, GuardedResponse, GuardedVlmImageRequest, GuardedVlmOcrRequest, ToolCallRequest
from app.orchestration import run_guarded_chat_flow, run_guarded_rag_flow, run_guarded_tool_call, run_guarded_vlm_flow
from app.services.guarded_runtime import (
    audit_store,
    session_risk_state,
)
from app.services.guarded_runtime import adapter_registry
from app.services.live_vlm_ocr import analyze_image_with_registered_vlm as analyze_image_with_local_vlm
from app.services.live_rag import retrieve_qdrant_bge

router = APIRouter()


_CONTEXTUAL_ENFORCEMENT_ORDER = {
    "ALLOW": 0,
    "ALLOW_WITH_CONSTRAINTS": 1,
    "REQUIRE_APPROVAL": 2,
    "QUARANTINE_AND_CONTINUE": 3,
    "DENY_ACTION": 4,
    "TERMINATE": 5,
}


def _portal_contextual_evaluate(raw_request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    manager = getattr(raw_request.app.state, "nf_portal_manager", None)
    service = getattr(manager, "service", None)
    if service is None:
        raise HTTPException(status_code=503, detail="Contextual Authorization runtime is unavailable")
    try:
        return service.evaluate_context(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _strongest_contextual_result(results: list[dict[str, Any]]) -> dict[str, Any] | None:
    restricted = [item for item in results if item["policy_decision"]["enforcement"] not in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}]
    if not restricted:
        return None
    return max(restricted, key=lambda item: _CONTEXTUAL_ENFORCEMENT_ORDER[item["policy_decision"]["enforcement"]])


def _contextual_guard_response(
    *,
    session_id: str,
    strongest: dict[str, Any],
    evaluations: list[dict[str, Any]],
    extra: dict[str, Any],
) -> dict[str, Any]:
    decision = strongest["policy_decision"]
    finding = strongest["model_finding"]
    evidence_ids = [item["evidence_replay_verify"]["record_hash"] for item in evaluations]
    return {
        "session_id": session_id,
        "model": strongest["provider"].get("model") or "task-relation-judge",
        "action": decision["action"],
        "answer": "GuardX 已隔离非可信内容中的控制指令；下游业务模型未被调用，原始任务可在保留事实内容后继续。",
        "risk_score": decision["risk_score"],
        "input_analysis": {"risk_score": decision["risk_score"], "labels": ["contextual_authorization"], "evidence": evidence_ids, "metadata": {}},
        "context_analysis": {"risk_score": decision["risk_score"], "labels": [finding["decision"]], "evidence": evidence_ids, "metadata": {}},
        "risk_findings": [
            {
                "risk_type": "task_relation_conflict",
                "risk_score": item["policy_decision"]["risk_score"],
                "severity": "high" if item["policy_decision"]["risk_score"] >= 0.7 else "medium",
                "evidence": [item["model_finding"]["evidence"].get("task_relation", {})],
                "metadata": {"run_id": item["run_id"], "surface": item["surface"]},
            }
            for item in evaluations
            if item["policy_decision"]["enforcement"] not in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}
        ],
        "policy_decision": decision,
        "defense_actions": [{"method": "contextual_quarantine", "runtime_action": decision["enforcement"]}],
        "model_invoked": False,
        "relation_model_invoked": any(bool(item.get("model_called")) for item in evaluations),
        "response_source": "guardx_contextual_policy_v2",
        "contextual_evaluations": evaluations,
        "evidence_ids": evidence_ids,
        **extra,
    }


@router.post("/v1/guarded/chat", response_model=GuardedResponse)
def guarded_chat(request: GuardedChatRequest) -> GuardedResponse:
    result = run_guarded_chat_flow(request)
    log_guarded_response(audit_store, flow=result.flow, response=result.response, trace_events=result.trace_events, decision_record=result.decision_record)
    return result.response




@router.post("/v1/guarded/rag_chat", response_model=GuardedResponse)
def guarded_rag_chat(request: GuardedRagRequest) -> GuardedResponse:
    result = run_guarded_rag_flow(request)
    log_guarded_response(audit_store, flow=result.flow, response=result.response, trace_events=result.trace_events, decision_record=result.decision_record)
    return result.response


@router.post("/v1/guarded/vlm_ocr_chat", response_model=GuardedResponse)
def guarded_vlm_ocr_chat(request: GuardedVlmOcrRequest) -> GuardedResponse:
    result = run_guarded_vlm_flow(request)
    log_guarded_response(audit_store, flow=result.flow, response=result.response, trace_events=result.trace_events, decision_record=result.decision_record)
    return result.response


@router.post("/v1/guarded/rag_demo_query")
def guarded_rag_demo_query(request: GuardedRagDemoRequest, raw_request: Request) -> dict[str, Any]:
    try:
        retrieval = retrieve_qdrant_bge(
            request.message,
            [document.model_dump(mode="json") for document in request.documents],
            top_k=request.top_k,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Qdrant + BGE-M3 retrieval failed: {exc}") from exc
    context_chunks = [
        f"[source={item['source']} chunk={item['chunk_id']} score={item['score']}]\n{item['text']}"
        for item in retrieval["chunks"]
    ]
    contextual_evaluations = [
        _portal_contextual_evaluate(
            raw_request,
            {
                "surface": "rag",
                "user_goal": request.message,
                "observation": item["text"],
                "session_context": f"retrieved chunk {item['chunk_id']} from {item['source']}",
            },
        )
        for item in retrieval["chunks"]
    ]
    strongest = _strongest_contextual_result(contextual_evaluations)
    retrieval_payload = {
        "retrieval_engine": retrieval["engine"],
        "retrieval_provider_mode": retrieval["provider_mode"],
        "retrieval_vector_store": retrieval["vector_store"],
        "retrieval_embedding_model": retrieval["embedding_model"],
        "retrieval_collection": retrieval["collection"],
        "retrieval_document_count": retrieval["document_count"],
        "retrieval_chunk_count": retrieval["chunk_count"],
        "retrieved_chunks": retrieval["chunks"],
    }
    if strongest is not None:
        return _contextual_guard_response(
            session_id=request.session_id,
            strongest=strongest,
            evaluations=contextual_evaluations,
            extra=retrieval_payload,
        )
    guarded_request = GuardedRagRequest(
        session_id=request.session_id,
        model=request.model,
        message=request.message,
        context_chunks=context_chunks,
        metadata={
            "surface": "rag",
            "source": "reviewer_live_rag",
            "retrieval_engine": retrieval["engine"],
            "retrieval_provider_mode": retrieval["provider_mode"],
            "retrieval_vector_store": retrieval["vector_store"],
            "retrieval_embedding_model": retrieval["embedding_model"],
            "retrieval_collection": retrieval["collection"],
            "retrieved_chunk_ids": [item["chunk_id"] for item in retrieval["chunks"]],
        },
    )
    result = run_guarded_rag_flow(guarded_request)
    log_guarded_response(
        audit_store,
        flow=result.flow,
        response=result.response,
        trace_events=result.trace_events,
        decision_record=result.decision_record,
    )
    return {
        **result.response.model_dump(mode="json"),
        **retrieval_payload,
        "contextual_guard_passed": True,
        "contextual_evaluations": contextual_evaluations,
        "evidence_ids": [item["evidence_replay_verify"]["record_hash"] for item in contextual_evaluations],
    }


@router.post("/v1/guarded/vlm_image_analyze")
def guarded_vlm_image_analyze(request: GuardedVlmImageRequest, raw_request: Request) -> dict[str, Any]:
    try:
        observation = analyze_image_with_local_vlm(
            image_base64=request.image_base64,
            mime_type=request.mime_type,
            user_prompt=request.message,
            model_name=request.vlm_model,
            registry=adapter_registry,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"VLM failed: {exc}") from exc

    contextual_evaluation = _portal_contextual_evaluate(
        raw_request,
        {
            "surface": "vlm",
            "user_goal": request.message,
            "observation": "\n".join(part for part in (observation["ocr_text"], observation["visual_caption"]) if part),
            "session_context": f"image sha256:{observation['image_sha256']}",
        },
    )
    strongest = _strongest_contextual_result([contextual_evaluation])
    observation_payload = {
        "vlm_provider": observation["provider"],
        "vlm_provider_mode": observation["provider_mode"],
        "vlm_model": observation["vlm_model"],
        "vlm_invoked": observation["vlm_invoked"],
        "vlm_latency_ms": observation["latency_ms"],
        "image_sha256": observation["image_sha256"],
        "image_bytes": observation["image_bytes"],
        "ocr_text": observation["ocr_text"],
        "visual_caption": observation["visual_caption"],
        "visual_risk_signals": observation["risk_signals"],
    }
    if strongest is not None:
        return _contextual_guard_response(
            session_id=request.session_id,
            strongest=strongest,
            evaluations=[contextual_evaluation],
            extra=observation_payload,
        )

    guarded_request = GuardedVlmOcrRequest(
        session_id=request.session_id,
        model=request.downstream_model,
        message=request.message,
        image_id=f"sha256:{observation['image_sha256'][:16]}",
        ocr_text=observation["ocr_text"],
        vlm_answer=observation["visual_caption"] or observation["raw_observation"],
        metadata={
            "surface": "vlm_ocr",
            "source": "reviewer_live_image",
            "filename": request.filename,
            "image_sha256": observation["image_sha256"],
            "visual_caption": observation["visual_caption"],
            "visual_risk_signals": observation["risk_signals"],
            "vlm_provider": observation["provider"],
            "vlm_model": observation["vlm_model"],
            "vlm_provider_mode": observation["provider_mode"],
        },
    )
    result = run_guarded_vlm_flow(guarded_request)
    log_guarded_response(
        audit_store,
        flow=result.flow,
        response=result.response,
        trace_events=result.trace_events,
        decision_record=result.decision_record,
    )
    return {
        **result.response.model_dump(mode="json"),
        **observation_payload,
        "contextual_guard_passed": True,
        "contextual_evaluations": [contextual_evaluation],
        "evidence_ids": [contextual_evaluation["evidence_replay_verify"]["record_hash"]],
    }




@router.post("/v1/guarded/tool_call")
def guarded_tool_call(request: ToolCallRequest) -> dict[str, Any]:
    session_id = request.session_id
    base_risk = session_risk_state[session_id]
    payload = run_guarded_tool_call(
        session_id=session_id,
        tool_name=request.tool_name,
        args=request.args,
        risk_hint=request.risk_hint,
        base_risk=base_risk,
        surface="agent_tool",
    )
    log_guarded_tool_result(audit_store, result=payload)
    return payload


