from app.models import GuardedResponse, GuardedVlmOcrRequest
from app.observability import guarded_trace_metadata, trace_id_from_metadata
from app.orchestration.generation_flow import run_vlm_generation
from app.orchestration.guarded_flow import finalize_guarded_policy, prepare_guarded_policy
from app.orchestration.guarded_route_result import GuardedRouteResult
from app.orchestration.lifecycle import build_decision_record, build_runtime_envelope
from app.orchestration.observation_envelopes import build_vlm_observation_envelopes
from app.risk_providers import build_vlm_segments
from app.services.defense_orchestrator import build_defense_actions, defense_trace_event
from app.services.guarded_runtime import (
    SETTINGS,
    analyze_direct_embedding,
    adapter_registry,
    apply_action,
    context_guard,
    embedding_guard,
    generate_with_guard_fallback,
    input_guard,
    maybe_merge_online_embedding,
    merge_risk_with_embedding_route,
    next_session_risk,
    output_guard,
    recover_benign_vlm_visual_training,
    session_risk_state,
)


def run_guarded_vlm_flow(request: GuardedVlmOcrRequest) -> GuardedRouteResult:
    session_id = request.session_id
    model = request.model or SETTINGS.default_model
    adapter = adapter_registry.get(model)

    observation_envelopes = build_vlm_observation_envelopes(request)
    ocr_context = [
        f"Untrusted {item.source} {item.provenance.source_uri}: {item.content}"
        for item in observation_envelopes
    ]
    visual_signals = request.metadata.get("visual_risk_signals") if isinstance(request.metadata, dict) else None
    if isinstance(visual_signals, list) and visual_signals:
        joined_signals = ", ".join(str(item) for item in visual_signals[:12])
        ocr_context.append(f"Untrusted image {request.image_id} visual risk signals: {joined_signals}")
    visual_caption = request.metadata.get("visual_caption") if isinstance(request.metadata, dict) else None
    if isinstance(visual_caption, str) and visual_caption.strip():
        ocr_context.append(f"Untrusted image {request.image_id} visual caption: {visual_caption.strip()[:1000]}")

    trust_segments = build_vlm_segments(
        request.message,
        ocr_text=request.ocr_text,
        vlm_answer=request.vlm_answer,
        visual_caption=visual_caption.strip() if isinstance(visual_caption, str) and visual_caption.strip() else None,
        visual_signals=visual_signals if isinstance(visual_signals, list) else None,
    )
    runtime_envelope = build_runtime_envelope(
        session_id=session_id,
        flow="vlm_ocr",
        surface="vlm",
        model=model,
        segments=trust_segments,
        metadata={
            **request.metadata,
            "observation_provenance": [item.as_authorization_context() for item in observation_envelopes],
        },
    )
    input_analysis = input_guard.analyze(f"{request.message}\n{request.ocr_text}", request.history)
    context_analysis = context_guard.analyze(ocr_context)
    embedding_analysis = analyze_direct_embedding(request.message, request.history, ocr_context)
    vlm_segments: list[tuple[str, str]] = [("user", request.message)]
    if request.ocr_text:
        vlm_segments.append(("ocr", request.ocr_text))
    if request.vlm_answer:
        vlm_segments.append(("vlm", request.vlm_answer))
    if isinstance(visual_caption, str) and visual_caption.strip():
        vlm_segments.append(("visual", visual_caption.strip()))
    if isinstance(visual_signals, list) and visual_signals:
        vlm_segments.append(("visual", ", ".join(str(item) for item in visual_signals[:12])))

    embedding_analysis = maybe_merge_online_embedding(
        embedding_analysis,
        "\n".join([request.message, *ocr_context]),
        surface="vlm_ocr",
        segments=vlm_segments,
    )
    prior_session_risk = session_risk_state[session_id]
    total_risk = merge_risk_with_embedding_route(input_analysis, context_analysis, prior_session_risk, embedding_analysis, surface="vlm_ocr")
    total_risk = recover_benign_vlm_visual_training(
        request=request,
        visual_signals=visual_signals,
        visual_caption=visual_caption,
        total_risk=total_risk,
        embedding_analysis=embedding_analysis,
    )
    policy_stage = prepare_guarded_policy(
        surface="vlm",
        total_risk=total_risk,
        input_analysis=input_analysis,
        context_analysis=context_analysis,
        embedding_analysis=embedding_analysis,
        segments=trust_segments,
        metadata=request.metadata,
        session_id=session_id,
    )

    generation = run_vlm_generation(
        action=policy_stage.action,
        message=request.message,
        history=request.history,
        vlm_answer=request.vlm_answer,
        adapter=adapter,
        model=model,
        apply_action=apply_action,
        generate_with_guard_fallback=generate_with_guard_fallback,
    )

    session_risk_state[session_id] = next_session_risk(
        prior_session_risk,
        input_analysis.risk_score,
        context_analysis.risk_score,
    )

    final_policy = finalize_guarded_policy(
        surface="vlm",
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
        event_type="guarded_vlm_ocr_chat",
        metadata=guarded_trace_metadata(metadata=request.metadata, surface="vlm"),
        output_threshold=None,
    )
    answer = output_guard.safe_refusal_message() if final_policy.output_redacted else generation.answer
    trace_metadata = guarded_trace_metadata(metadata=request.metadata, surface="vlm")
    defense_actions = build_defense_actions(
        flow="vlm_ocr",
        policy_decision=final_policy.policy_decision,
        risk_findings=final_policy.risk_findings,
        trust_boundary="untrusted_image_evidence",
        explicit_attack_vector=str(request.metadata.get("attack_vector", "")),
    )
    if defense_actions:
        final_policy.trace_events.append(
            defense_trace_event(
                trace_id=trace_id_from_metadata(trace_metadata, fallback=session_id),
                payload_ref=f"{session_id}:guarded_vlm_ocr_chat",
                defense_actions=defense_actions,
                metadata=trace_metadata,
            )
        )
    response = GuardedResponse(
        session_id=session_id,
        model=model,
        action=final_policy.action,
        answer=answer,
        upstream_model_output=generation.upstream_model_output,
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
    return GuardedRouteResult(flow="vlm_ocr", response=response, trace_events=final_policy.trace_events, decision_record=decision_record)
