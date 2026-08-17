from typing import Any
from uuid import uuid4

from app.observability import proxy_trace_metadata
from app.orchestration.guarded_flow import finalize_guarded_policy, prepare_guarded_policy
from app.risk_providers import build_rag_segments
from app.services.guarded_runtime import (
    analyze_direct_embedding,
    context_guard,
    embedding_guard,
    input_guard,
    maybe_merge_online_embedding,
    merge_risk_with_embedding_route,
    next_session_risk,
    session_risk_state,
)


def replay_id(payload: dict[str, Any], request_id: str | None) -> str:
    return str(payload.get("replay_id") or request_id or f"gx-replay-{uuid4().hex}")


def normalized_context(payload: dict[str, Any], fallback: list[str] | None = None) -> list[str]:
    context_chunks = payload.get("context_chunks")
    if not isinstance(context_chunks, list):
        context_chunks = fallback or []
    return [str(chunk) for chunk in context_chunks]


def prepare_proxy_policy(
    *,
    session_id: str,
    message: str,
    context_chunks: list[str],
    metadata: dict[str, Any] | None = None,
) -> tuple[Any, Any, Any, float, Any, list[Any]]:
    trust_segments = build_rag_segments(message, context_chunks)
    input_analysis = input_guard.analyze(message, [])
    context_analysis = context_guard.analyze(context_chunks)
    embedding_analysis = analyze_direct_embedding(message, [], context_chunks)
    proxy_segments = [("user", message), *[("context", chunk) for chunk in context_chunks]]
    embedding_analysis = maybe_merge_online_embedding(
        embedding_analysis,
        "\n".join([message, *context_chunks]),
        surface="rag",
        segments=proxy_segments,
    )
    prior_session_risk = session_risk_state[session_id]
    total_risk = merge_risk_with_embedding_route(input_analysis, context_analysis, prior_session_risk, embedding_analysis, surface="rag")
    policy_stage = prepare_guarded_policy(
        surface="rag",
        total_risk=total_risk,
        input_analysis=input_analysis,
        context_analysis=context_analysis,
        embedding_analysis=embedding_analysis,
        segments=trust_segments,
        metadata=metadata,
        session_id=session_id,
    )
    return input_analysis, context_analysis, embedding_analysis, total_risk, policy_stage, trust_segments


def finalize_proxy_policy(
    *,
    session_id: str,
    event_type: str,
    replay_id: str,
    workspace_slug: str | None = None,
    metadata: dict[str, Any] | None = None,
    total_risk: float,
    action: str,
    policy_stage: Any,
    input_analysis: Any,
    context_analysis: Any,
    embedding_analysis: Any,
    output_analysis: Any,
    trust_segments: list[Any],
) -> Any:
    session_risk_state[session_id] = next_session_risk(
        session_risk_state[session_id],
        input_analysis.risk_score,
        context_analysis.risk_score,
    )
    trace_metadata = proxy_trace_metadata(
        metadata=metadata,
        replay_id=replay_id,
        workspace_slug=workspace_slug,
        surface="rag",
    )
    return finalize_guarded_policy(
        surface="rag",
        total_risk=total_risk,
        current_action=action,
        policy_decision=policy_stage.policy_decision,
        input_analysis=input_analysis,
        context_analysis=context_analysis,
        embedding_analysis=embedding_analysis,
        output_analysis=output_analysis,
        segments=trust_segments,
        provider_findings=policy_stage.provider_findings,
        session_id=session_id,
        event_type=event_type,
        metadata=trace_metadata,
        output_threshold=None,
    )
