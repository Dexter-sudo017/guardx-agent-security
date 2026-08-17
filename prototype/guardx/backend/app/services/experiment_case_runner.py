from time import perf_counter

from app.audit.logger import log_action_decision, log_action_observation, log_guarded_response
from app.models import ActionGuardRequest, ActionObservationRequest, GuardedChatRequest, GuardedRagRequest, GuardedVlmOcrRequest
from app.orchestration import (
    run_action_decision_flow,
    run_action_observation_flow,
    run_guarded_chat_flow,
    run_guarded_rag_flow,
    run_guarded_vlm_flow,
)
from app.services.experiment_case_metadata import experiment_case_metadata
from app.services.runtime_state import audit_store


def _metadata(*, suite_id: str, case_id: str, policy_profile: str, session_id: str, seed: int, case: object | None = None) -> dict:
    metadata = {"trace_id": f"{session_id}-{case_id}-trace", "suite_id": suite_id, "case_id": case_id, "policy_profile": policy_profile, "seed": seed}
    if case is not None:
        for attr in ("attack_vector", "trust_boundary", "expectation", "benchmark_family", "security_property"):
            value = getattr(case, attr, None)
            if value is not None:
                metadata[attr] = value
    return metadata


def _case_result(case_id: str, surface: str, response: object) -> dict:
    policy_decision = getattr(response, "policy_decision", None)
    raw_risk = float(getattr(response, "risk_score", 0.0) or 0.0)
    policy_risk = float(getattr(policy_decision, "risk_score", raw_risk) or raw_risk) if policy_decision else raw_risk
    risk_findings = list(getattr(response, "risk_findings", []) or [])
    risk_provider_failures = []
    for finding in risk_findings:
        for ref in list(getattr(finding, "evidence_refs", []) or []):
            if ref.startswith(("provider_error:", "sidecar_unavailable:", "provider_circuit_open")):
                risk_provider_failures.append({"provider_id": getattr(finding, "provider_id", "unknown"), "evidence_ref": ref})
    embedding_analysis = getattr(response, "embedding_analysis", None)
    embedding_metadata = dict(getattr(embedding_analysis, "metadata", {}) or {})
    embedding_errors = []
    if embedding_metadata.get("qwen3_joint_online_error"):
        embedding_errors.append({"component": "qwen3_online_embedguard", "error": str(embedding_metadata["qwen3_joint_online_error"])[:240]})
    output_text = str(
        getattr(response, "answer", "")
        or getattr(response, "observation", "")
        or getattr(response, "sanitized_observation", "")
        or ""
    )
    return {
        "case_id": case_id,
        "surface": surface,
        "risk_score": policy_risk,
        "raw_risk_score": raw_risk,
        "route": getattr(policy_decision, "route", "unknown") if policy_decision else "unknown",
        "action": getattr(policy_decision, "action", getattr(response, "action", "unknown")) if policy_decision else getattr(response, "action", "unknown"),
        "risk_provider_ids": sorted({str(getattr(finding, "provider_id", "unknown")) for finding in risk_findings}),
        "defense_action_ids": sorted({str(item.get("defense_id", "unknown")) for item in list(getattr(response, "defense_actions", []) or [])}),
        "runtime_actions": sorted({str(item.get("runtime_action", "unknown")) for item in list(getattr(response, "defense_actions", []) or [])}),
        "risk_provider_failure_count": len(risk_provider_failures),
        "risk_provider_failures": risk_provider_failures,
        "embedding_labels": list(getattr(embedding_analysis, "labels", []) or []),
        "embedding_metadata_keys": sorted(str(key) for key in embedding_metadata.keys()),
        "embedding_errors": embedding_errors,
        "output_preview": output_text[:240],
    }


def _run_chat_case(*, session_id: str, suite_id: str, case_id: str, policy_profile: str, seed: int, model: str, case: object) -> dict:
    request = GuardedChatRequest(
        session_id=session_id,
        model=model,
        message=getattr(case, "message"),
        history=getattr(case, "history"),
        metadata=_metadata(suite_id=suite_id, case_id=case_id, policy_profile=policy_profile, session_id=session_id, seed=seed, case=case),
    )
    result = run_guarded_chat_flow(request)
    log_guarded_response(audit_store, flow=result.flow, response=result.response, trace_events=result.trace_events, decision_record=result.decision_record)
    return _case_result(case_id, "chat", result.response)


def _run_rag_case(*, session_id: str, suite_id: str, case_id: str, policy_profile: str, seed: int, model: str, case: object) -> dict:
    request = GuardedRagRequest(
        session_id=session_id,
        model=model,
        message=getattr(case, "message"),
        history=getattr(case, "history"),
        context_chunks=[getattr(case, "context")],
        metadata=_metadata(suite_id=suite_id, case_id=case_id, policy_profile=policy_profile, session_id=session_id, seed=seed, case=case),
    )
    result = run_guarded_rag_flow(request)
    log_guarded_response(audit_store, flow=result.flow, response=result.response, trace_events=result.trace_events, decision_record=result.decision_record)
    return _case_result(case_id, "rag", result.response)


def _run_vlm_case(*, session_id: str, suite_id: str, case_id: str, policy_profile: str, seed: int, model: str, case: object) -> dict:
    request = GuardedVlmOcrRequest(
        session_id=session_id,
        model=model,
        message=getattr(case, "message"),
        history=getattr(case, "history"),
        image_id=getattr(case, "image_id"),
        ocr_text=getattr(case, "ocr_text"),
        vlm_answer=getattr(case, "vlm_answer"),
        metadata=_metadata(suite_id=suite_id, case_id=case_id, policy_profile=policy_profile, session_id=session_id, seed=seed, case=case),
    )
    result = run_guarded_vlm_flow(request)
    log_guarded_response(audit_store, flow=result.flow, response=result.response, trace_events=result.trace_events, decision_record=result.decision_record)
    return _case_result(case_id, "vlm_ocr", result.response)


def _run_action_case(*, session_id: str, suite_id: str, case_id: str, policy_profile: str, seed: int, case: object) -> dict:
    metadata = _metadata(suite_id=suite_id, case_id=case_id, policy_profile=policy_profile, session_id=session_id, seed=seed, case=case)
    request = ActionGuardRequest(
        replay_id=metadata["trace_id"],
        session_id=session_id,
        surface=getattr(case, "surface"),
        action=getattr(case, "action"),
        task_context=metadata,
        risk_hint=getattr(case, "risk_hint"),
    )
    result = run_action_decision_flow(request)
    log_action_decision(audit_store, request=request, response=result.response, execution=result.execution, trace_events=result.trace_events, decision_record=result.decision_record)
    return _case_result(case_id, "agent_tool", result.response)


def _run_observation_case(*, session_id: str, suite_id: str, case_id: str, policy_profile: str, seed: int, case: object) -> dict:
    metadata = _metadata(suite_id=suite_id, case_id=case_id, policy_profile=policy_profile, session_id=session_id, seed=seed, case=case)
    request = ActionObservationRequest(
        replay_id=metadata["trace_id"],
        session_id=session_id,
        surface=getattr(case, "surface"),
        action=getattr(case, "action"),
        observation=getattr(case, "observation"),
        metadata=metadata,
    )
    result = run_action_observation_flow(request)
    log_action_observation(audit_store, request=request, response=result.response, trace_events=result.trace_events, decision_record=result.decision_record)
    return _case_result(case_id, "agent_tool", result.response)


def run_config_case(*, session_id: str, suite_id: str, policy_profile: str, seed: int, index: int, model: str, case: object) -> dict:
    case_id = getattr(case, "case_id")
    kind = getattr(case, "kind")
    common = {"session_id": session_id, "suite_id": suite_id, "case_id": case_id, "policy_profile": policy_profile, "seed": seed + index}
    started = perf_counter()
    if kind == "chat":
        result = _run_chat_case(**common, model=model, case=case)
    elif kind == "rag":
        result = _run_rag_case(**common, model=model, case=case)
    elif kind == "vlm_ocr":
        result = _run_vlm_case(**common, model=model, case=case)
    elif kind == "observation":
        result = _run_observation_case(**common, case=case)
    else:
        result = _run_action_case(**common, case=case)
    result["latency_ms"] = round((perf_counter() - started) * 1000.0, 3)
    result["expectation"] = getattr(case, "expectation", "mixed")
    result["expected_routes"] = list(getattr(case, "expected_routes", []) or [])
    result["expected_route_match"] = result["route"] in result["expected_routes"] if result["expected_routes"] else None
    result.update(experiment_case_metadata(case))
    return result
