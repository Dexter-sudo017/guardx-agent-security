from typing import Any, Callable

from fastapi import HTTPException, Request

from app.audit.logger import log_guarded_response
from app.models import GuardedVlmImageRequest, GuardedVlmOcrRequest
from app.services.contextual_live_response import blocked_response, evaluate_context, strongest_result
from app.services.guarded_runtime import audit_store


def run_vlm_image(request: GuardedVlmImageRequest, raw_request: Request, *, analyze_image: Callable, registry: Any, vlm_flow: Callable) -> dict[str, Any]:
    try:
        observation = analyze_image(image_base64=request.image_base64, mime_type=request.mime_type, user_prompt=request.message, model_name=request.vlm_model, registry=registry)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"VLM failed: {exc}") from exc
    evaluation = evaluate_context(raw_request, {"surface": "vlm", "user_goal": request.message, "observation": "\n".join(part for part in (observation["ocr_text"], observation["visual_caption"]) if part), "session_context": f"image sha256:{observation['image_sha256']}"})
    extra = {"vlm_provider": observation["provider"], "vlm_provider_mode": observation["provider_mode"], "vlm_model": observation["vlm_model"], "vlm_invoked": observation["vlm_invoked"], "vlm_latency_ms": observation["latency_ms"], "image_sha256": observation["image_sha256"], "image_bytes": observation["image_bytes"], "ocr_text": observation["ocr_text"], "visual_caption": observation["visual_caption"], "visual_risk_signals": observation["risk_signals"]}
    strongest = strongest_result([evaluation])
    if strongest is not None:
        return blocked_response(session_id=request.session_id, strongest=strongest, evaluations=[evaluation], extra=extra)
    guarded_request = GuardedVlmOcrRequest(
        session_id=request.session_id, model=request.downstream_model, message=request.message,
        image_id=f"sha256:{observation['image_sha256'][:16]}", ocr_text=observation["ocr_text"], vlm_answer=observation["visual_caption"] or observation["raw_observation"],
        metadata={"surface": "vlm_ocr", "source": "reviewer_live_image", "filename": request.filename, "image_sha256": observation["image_sha256"], "visual_caption": observation["visual_caption"], "visual_risk_signals": observation["risk_signals"], "vlm_provider": observation["provider"], "vlm_model": observation["vlm_model"], "vlm_provider_mode": observation["provider_mode"]},
    )
    result = vlm_flow(guarded_request)
    log_guarded_response(audit_store, flow=result.flow, response=result.response, trace_events=result.trace_events, decision_record=result.decision_record)
    return {**result.response.model_dump(mode="json"), **extra, "contextual_guard_passed": True, "contextual_evaluations": [evaluation], "evidence_ids": [evaluation["evidence_replay_verify"]["record_hash"]]}
