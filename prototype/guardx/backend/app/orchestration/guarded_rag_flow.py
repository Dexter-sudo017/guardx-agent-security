from app.models import GuardedRagRequest, GuardedResponse
from app.observability import guarded_trace_metadata, trace_id_from_metadata
from app.orchestration.generation_flow import run_rag_generation
from app.orchestration.guarded_flow import finalize_guarded_policy, prepare_guarded_policy
from app.orchestration.guarded_route_result import GuardedRouteResult
from app.orchestration.lifecycle import build_decision_record, build_runtime_envelope
from app.risk_providers import build_rag_segments
from app.services.defense_orchestrator import build_defense_actions, defense_trace_event
from app.services.guarded_runtime import (
    SETTINGS,
    analyze_direct_embedding,
    adapter_registry,
    allowed_refusal_recovery,
    apply_action,
    context_guard,
    embedding_guard,
    generate_with_guard_fallback,
    guarded_rag_prompt,
    input_guard,
    is_refusal_like,
    maybe_merge_online_embedding,
    merge_risk_with_embedding_route,
    next_session_risk,
    output_guard,
    session_risk_state,
)


def run_guarded_rag_flow(request: GuardedRagRequest) -> GuardedRouteResult:
    session_id = request.session_id
    model = request.model or SETTINGS.default_model
    adapter = adapter_registry.get(model)
    trust_segments = build_rag_segments(request.message, [str(chunk) for chunk in request.context_chunks])
    runtime_envelope = build_runtime_envelope(
        session_id=session_id,
        flow="rag",
        surface="rag",
        model=model,
        segments=trust_segments,
        metadata=request.metadata,
    )

    input_analysis = input_guard.analyze(request.message, request.history)
    context_analysis = context_guard.analyze(request.context_chunks)
    embedding_analysis = analyze_direct_embedding(request.message, request.history, request.context_chunks)
    rag_segments = [("user", request.message), *[("context", chunk) for chunk in request.context_chunks]]
    embedding_analysis = maybe_merge_online_embedding(
        embedding_analysis,
        "\n".join([request.message, *request.context_chunks]),
        surface="rag",
        segments=rag_segments,
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
        metadata=request.metadata,
        session_id=session_id,
    )

    generation = run_rag_generation(
        action=policy_stage.action,
        message=request.message,
        history=request.history,
        context_chunks=request.context_chunks,
        context_risk_score=context_analysis.risk_score,
        adapter=adapter,
        model=model,
        total_risk=total_risk,
        medium_threshold=SETTINGS.thresholds.medium,
        apply_action=apply_action,
        generate_with_guard_fallback=generate_with_guard_fallback,
        is_refusal_like=is_refusal_like,
        allowed_refusal_recovery=allowed_refusal_recovery,
        guarded_rag_prompt=guarded_rag_prompt,
    )

    session_risk_state[session_id] = next_session_risk(
        prior_session_risk,
        input_analysis.risk_score,
        context_analysis.risk_score,
    )

    final_policy = finalize_guarded_policy(
        surface="rag",
        total_risk=total_risk,
        current_action=generation.action,
        policy_decision=policy_stage.policy_decision,
        input_analysis=input_analysis,
        context_analysis=context_analysis,
        embedding_analysis=embedding_analysis,
        output_analysis=generation.output_analysis,
        segments=trust_segments,
        provider_findings=policy_stage.provider_findings,
        session_id=session_id,
        event_type="guarded_rag_chat",
        metadata=guarded_trace_metadata(metadata=request.metadata, surface="rag"),
        output_threshold=None,
    )
    answer = output_guard.safe_refusal_message() if final_policy.output_redacted else generation.answer
    trace_metadata = guarded_trace_metadata(metadata=request.metadata, surface="rag")
    defense_actions = build_defense_actions(
        flow="rag",
        policy_decision=final_policy.policy_decision,
        risk_findings=final_policy.risk_findings,
        trust_boundary="untrusted_retrieved_context",
        explicit_attack_vector=str(request.metadata.get("attack_vector", "")),
    )
    if defense_actions:
        final_policy.trace_events.append(
            defense_trace_event(
                trace_id=trace_id_from_metadata(trace_metadata, fallback=session_id),
                payload_ref=f"{session_id}:guarded_rag_chat",
                defense_actions=defense_actions,
                metadata=trace_metadata,
            )
        )
    response = GuardedResponse(
        session_id=session_id,
        model=model,
        action=final_policy.action,
        answer=answer,
        risk_score=total_risk,
        input_analysis=input_analysis,
        embedding_analysis=embedding_analysis,
        context_analysis=context_analysis,
        output_analysis=generation.output_analysis,
        tool_decisions=[],
        risk_findings=final_policy.risk_findings,
        policy_decision=final_policy.policy_decision,
        defense_actions=defense_actions,
        model_invoked=generation.model_invoked,
        response_source="guardx_output_guard" if final_policy.output_redacted else generation.response_source,
    )
    decision_record = build_decision_record(
        envelope=runtime_envelope,
        stage="output",
        risk_findings=final_policy.risk_findings,
        policy_decision=final_policy.policy_decision,
        trace_events=final_policy.trace_events,
    )
    return GuardedRouteResult(flow="rag", response=response, trace_events=final_policy.trace_events, decision_record=decision_record)
