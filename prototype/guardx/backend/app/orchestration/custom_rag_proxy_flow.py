from time import perf_counter
from typing import Any

from app.models import AnalysisResult
from app.orchestration.lifecycle import build_decision_record, build_runtime_envelope
from app.orchestration.proxy_shared_flow import finalize_proxy_policy, normalized_context, prepare_proxy_policy, replay_id
from app.services.guarded_runtime import output_guard
from app.services.proxy_runtime import blocking_action, extract_answer_text, forward_json_target


def run_custom_rag_proxy_flow(
    *,
    payload: dict[str, Any],
    request_id: str | None = None,
) -> dict[str, Any]:
    request_started = perf_counter()
    message = str(payload.get("message", ""))
    session_id = str(payload.get("session_id") or "custom-rag-proxy")
    replay = replay_id(payload, request_id)
    base_url = str(payload.get("base_url") or "").rstrip("/")
    target_path = str(payload.get("path") or "/")
    url = f"{base_url}{target_path if target_path.startswith('/') else '/' + target_path}"
    context_chunks = normalized_context(payload)
    headers = payload.get("headers")
    if not isinstance(headers, dict):
        headers = {}
    headers = {str(key): str(value) for key, value in headers.items() if str(key).lower() not in {"host", "content-length"}}
    answer_fields = payload.get("answer_fields")
    if not isinstance(answer_fields, list):
        answer_fields = []
    trace_metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}

    input_analysis, context_analysis, embedding_analysis, total_risk, policy_stage, trust_segments = prepare_proxy_policy(
        session_id=session_id,
        message=message,
        context_chunks=context_chunks,
        metadata=trace_metadata,
    )
    runtime_envelope = build_runtime_envelope(
        request_id=replay,
        session_id=session_id,
        flow="proxy",
        surface="rag",
        segments=trust_segments,
        metadata={**trace_metadata, "replay_id": replay},
    )
    action = policy_stage.action
    target_called = False
    upstream = None
    output_analysis = AnalysisResult(risk_score=0.0, labels=[], evidence=[])

    if blocking_action(action):
        answer = output_guard.safe_refusal_message()
    elif not base_url:
        action = "block"
        answer = "GuardX proxy blocked forwarding because custom RAG base_url is missing."
    else:
        target_payload = payload.get("target_payload")
        if not isinstance(target_payload, dict):
            target_payload = {}
        message_field = str(payload.get("message_field") or "message")
        context_field = str(payload.get("context_field") or "context_chunks")
        target_payload.setdefault(message_field, message)
        target_payload.setdefault(context_field, context_chunks)
        upstream = forward_json_target(url, headers, target_payload)
        target_called = True
        answer_text = extract_answer_text(upstream.get("body") if isinstance(upstream, dict) else {}, [str(item) for item in answer_fields])
        output_analysis = output_guard.analyze(answer_text)
        answer = answer_text

    final_policy = finalize_proxy_policy(
        session_id=session_id,
        event_type="custom_rag_proxy_chat",
        replay_id=replay,
        metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else None,
        total_risk=total_risk,
        action=action,
        policy_stage=policy_stage,
        input_analysis=input_analysis,
        context_analysis=context_analysis,
        embedding_analysis=embedding_analysis,
        output_analysis=output_analysis,
        trust_segments=trust_segments,
    )
    if final_policy.output_redacted:
        answer = output_guard.safe_refusal_message()
    decision_record = build_decision_record(
        envelope=runtime_envelope,
        stage="output",
        risk_findings=final_policy.risk_findings,
        policy_decision=final_policy.policy_decision,
        trace_events=final_policy.trace_events,
    )
    return {
        "schema_version": "guardx-custom-rag-proxy-v1",
        "replay_id": replay,
        "session_id": session_id,
        "target_url": url if base_url else "",
        "action": final_policy.action,
        "target_called": target_called,
        "risk_score": total_risk,
        "input_analysis": input_analysis.model_dump(),
        "embedding_analysis": embedding_analysis.model_dump(),
        "context_analysis": context_analysis.model_dump(),
        "output_analysis": output_analysis.model_dump(),
        "risk_findings": [item.model_dump() for item in final_policy.risk_findings],
        "policy_decision": final_policy.policy_decision.model_dump(),
        "trace_events": final_policy.trace_events,
        "decision_record": decision_record.model_dump(),
        "answer": answer,
        "upstream": upstream if target_called else None,
        "latency_ms": round((perf_counter() - request_started) * 1000.0, 3),
        "target_latency_ms": upstream.get("latency_ms") if isinstance(upstream, dict) else 0.0,
        "cost": {
            "target_call_suppressed": not target_called,
            "target_calls": 1 if target_called else 0,
            "estimated_target_call_units_saved": 0 if target_called else 1,
        },
    }
