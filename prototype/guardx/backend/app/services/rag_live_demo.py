from typing import Any, Callable

from fastapi import HTTPException, Request

from app.audit.logger import log_guarded_response
from app.models import GuardedRagDemoRequest, GuardedRagFileRequest, GuardedRagRequest, RagDemoDocument
from app.services.contextual_live_response import blocked_response, evaluate_context, strongest_result
from app.services.document_ingestion import parse_file_payloads
from app.services.guarded_runtime import audit_store


def _retrieval_payload(retrieval: dict[str, Any]) -> dict[str, Any]:
    return {
        "retrieval_engine": retrieval["engine"], "retrieval_provider_mode": retrieval["provider_mode"],
        "retrieval_vector_store": retrieval["vector_store"], "retrieval_embedding_model": retrieval["embedding_model"],
        "retrieval_reranker_provider": retrieval.get("reranker_provider", "not-reported"),
        "retrieval_reranker_model": retrieval.get("reranker_model", "not-reported"),
        "retrieval_collection": retrieval["collection"], "retrieval_document_count": retrieval["document_count"],
        "retrieval_chunk_count": retrieval["chunk_count"], "retrieval_candidate_count": retrieval.get("candidate_count", len(retrieval["chunks"])),
        "retrieval_candidate_chunks": retrieval.get("candidate_chunks", retrieval["chunks"]),
        "retrieved_chunks": retrieval["chunks"],
    }


def run_rag_demo(request: GuardedRagDemoRequest, raw_request: Request, *, retrieve: Callable, rag_flow: Callable) -> dict[str, Any]:
    try:
        retrieval = retrieve(request.message, [document.model_dump(mode="json") for document in request.documents], top_k=request.top_k)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Qdrant + BGE-M3 retrieval failed: {exc}") from exc
    contexts = [f"[source={item['source']} chunk={item['chunk_id']} score={item['score']}]\n{item['text']}" for item in retrieval["chunks"]]
    guarded_candidates = retrieval.get("candidate_chunks", retrieval["chunks"])
    evaluations = [evaluate_context(raw_request, {"surface": "rag", "user_goal": request.message, "observation": item["text"], "session_context": f"retrieved candidate {item['chunk_id']} from {item['source']}"}) for item in guarded_candidates]
    strongest = strongest_result(evaluations)
    retrieval_payload = _retrieval_payload(retrieval)
    if strongest is not None:
        return blocked_response(session_id=request.session_id, strongest=strongest, evaluations=evaluations, extra=retrieval_payload)
    guarded_request = GuardedRagRequest(
        session_id=request.session_id, model=request.model, message=request.message, context_chunks=contexts,
        metadata={"surface": "rag", "source": "reviewer_live_rag", "retrieval_engine": retrieval["engine"], "retrieval_provider_mode": retrieval["provider_mode"], "retrieval_vector_store": retrieval["vector_store"], "retrieval_embedding_model": retrieval["embedding_model"], "retrieval_reranker_provider": retrieval.get("reranker_provider", "not-reported"), "retrieval_reranker_model": retrieval.get("reranker_model", "not-reported"), "retrieval_collection": retrieval["collection"], "retrieved_chunk_ids": [item["chunk_id"] for item in retrieval["chunks"]]},
    )
    result = rag_flow(guarded_request)
    log_guarded_response(audit_store, flow=result.flow, response=result.response, trace_events=result.trace_events, decision_record=result.decision_record)
    return {**result.response.model_dump(mode="json"), **retrieval_payload, "contextual_guard_passed": True, "contextual_evaluations": evaluations, "evidence_ids": [item["evidence_replay_verify"]["record_hash"] for item in evaluations]}


def run_rag_files(request: GuardedRagFileRequest, raw_request: Request, *, retrieve: Callable, rag_flow: Callable) -> dict[str, Any]:
    try:
        documents, manifest = parse_file_payloads(request.files)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Docling file parsing failed: {exc}") from exc
    payload = run_rag_demo(GuardedRagDemoRequest(session_id=request.session_id, model=request.model, message=request.message, documents=[RagDemoDocument(**item) for item in documents], top_k=request.top_k), raw_request, retrieve=retrieve, rag_flow=rag_flow)
    return {**payload, "document_manifest": manifest, "document_parser": "docling"}
