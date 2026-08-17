import os
from time import perf_counter
from typing import Any

from app.models import AnalysisResult
from app.orchestration.lifecycle import build_decision_record, build_runtime_envelope
from app.orchestration.proxy_shared_flow import finalize_proxy_policy, normalized_context, prepare_proxy_policy, replay_id
from app.services.guarded_runtime import output_guard
from app.services.proxy_runtime import (
    ANYTHINGLLM_WORKSPACE_CONFIG,
    ANYTHINGLLM_WORKSPACE_EXAMPLE_CONFIG,
    anythingllm_context_for_workspace,
    anythingllm_workspace_config,
    blocking_action,
    forward_anythingllm,
)


def run_anythingllm_proxy_flow(
    *,
    workspace_slug: str,
    payload: dict[str, Any],
    request_id: str | None = None,
) -> dict[str, Any]:
    request_started = perf_counter()
    message = str(payload.get("message", ""))
    workspace_config = anythingllm_workspace_config(workspace_slug)
    mode = str(payload.get("mode") or workspace_config.get("mode") or "query")
    session_id = str(payload.get("session_id") or f"anythingllm-proxy-{workspace_slug}")
    replay = replay_id(payload, request_id)
    base_url = str(payload.get("base_url") or workspace_config.get("base_url") or os.environ.get("ANYTHINGLLM_BASE_URL") or "http://localhost:3001")
    configured_api_env = str(workspace_config.get("api_key_env") or "ANYTHINGLLM_API_KEY")
    api_key = str(payload.get("api_key") or os.environ.get(configured_api_env) or os.environ.get("ANYTHINGLLM_API_KEY") or "")
    context_chunks = normalized_context(payload, fallback=anythingllm_context_for_workspace(workspace_slug))
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
        metadata={**trace_metadata, "replay_id": replay, "workspace_slug": workspace_slug},
    )
    action = policy_stage.action
    target_called = False
    upstream = None
    output_analysis = AnalysisResult(risk_score=0.0, labels=[], evidence=[])

    if blocking_action(action):
        answer = output_guard.safe_refusal_message()
    elif not api_key:
        action = "block"
        answer = "GuardX proxy blocked forwarding because AnythingLLM API key is not configured."
    else:
        target_payload = {key: value for key, value in payload.items() if key not in {"api_key", "base_url", "context_chunks", "model", "session_id", "replay_id"}}
        target_payload["message"] = message
        target_payload["mode"] = mode
        upstream = forward_anythingllm(
            base_url,
            workspace_slug,
            api_key,
            target_payload,
            timeout=int(payload.get("timeout_seconds") or workspace_config.get("timeout_seconds") or 240),
        )
        target_called = True
        answer_text = ""
        if isinstance(upstream.get("body"), dict):
            answer_text = str(upstream["body"].get("textResponse") or upstream["body"].get("answer") or "")
        output_analysis = output_guard.analyze(answer_text)
        answer = answer_text

    final_policy = finalize_proxy_policy(
        session_id=session_id,
        event_type="anythingllm_proxy_chat",
        replay_id=replay,
        workspace_slug=workspace_slug,
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
        "schema_version": "guardx-anythingllm-proxy-v1",
        "replay_id": replay,
        "session_id": session_id,
        "workspace_slug": workspace_slug,
        "base_url": base_url,
        "action": final_policy.action,
        "target_called": target_called,
        "risk_score": total_risk,
        "input_analysis": input_analysis.model_dump(),
        "embedding_analysis": embedding_analysis.model_dump(),
        "context_analysis": context_analysis.model_dump(),
        "risk_findings": [item.model_dump() for item in final_policy.risk_findings],
        "policy_decision": final_policy.policy_decision.model_dump(),
        "trace_events": final_policy.trace_events,
        "decision_record": decision_record.model_dump(),
        "answer": answer,
        "upstream": upstream if target_called else None,
        "latency_ms": round((perf_counter() - request_started) * 1000.0, 3),
        "target_latency_ms": upstream.get("latency_ms") if isinstance(upstream, dict) else 0.0,
        "workspace_config": {
            "config_used": ANYTHINGLLM_WORKSPACE_CONFIG.exists() or ANYTHINGLLM_WORKSPACE_EXAMPLE_CONFIG.exists(),
            "api_key_env": configured_api_env,
            "context_file": workspace_config.get("context_file"),
            "timeout_seconds": workspace_config.get("timeout_seconds"),
        },
        "cost": {
            "target_call_suppressed": not target_called,
            "target_calls": 1 if target_called else 0,
            "estimated_target_call_units_saved": 0 if target_called else 1,
        },
    }
