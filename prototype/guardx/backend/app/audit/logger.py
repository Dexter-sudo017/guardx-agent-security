from typing import Any, Literal

from app.audit.event_builder import (
    audit_dump,
    build_request_decision_audit_payload,
    build_response_audit_payload,
    build_result_audit_payload,
)


GuardedFlow = Literal["chat", "rag", "vlm_ocr"]
ProxyFlow = Literal["anythingllm", "custom_rag"]
BaselineFlow = Literal["chat", "rag", "tool_call"]

_GUARDED_EVENT_TYPES = {
    "chat": "guarded_chat",
    "rag": "guarded_rag_chat",
    "vlm_ocr": "guarded_vlm_ocr_chat",
}

_PROXY_EVENT_TYPES = {
    "anythingllm": "anythingllm_proxy_chat",
    "custom_rag": "custom_rag_proxy_chat",
}

_BASELINE_EVENT_TYPES = {
    "chat": "baseline_chat",
    "rag": "baseline_rag_chat",
    "tool_call": "baseline_tool_call",
}


def _field(value: Any, key: str, default: Any = None) -> Any:
    if hasattr(value, key):
        return getattr(value, key)
    if isinstance(value, dict):
        return value.get(key, default)
    return default


def _risk_score(value: Any, default: float = 0.0) -> float:
    raw = _field(value, "risk_score", default)
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


def _result_risk_score(result: dict[str, Any], default: float = 0.0) -> float:
    missing = object()
    raw = result.get("risk_score", missing)
    if raw is missing:
        raw = result.get("risk", missing)
    output_analysis = result.get("output_analysis")
    if raw is missing and isinstance(output_analysis, dict):
        raw = output_analysis.get("risk_score", default)
    if raw is missing:
        raw = default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


def _session_id(value: Any) -> str:
    return str(_field(value, "session_id", "default-session"))


def log_guarded_response(
    audit_store: Any,
    *,
    flow: GuardedFlow,
    response: Any,
    trace_events: list[dict[str, Any]],
    decision_record: Any = None,
) -> None:
    audit_store.log(
        session_id=_session_id(response),
        event_type=_GUARDED_EVENT_TYPES[flow],
        risk_score=_risk_score(response),
        payload=build_response_audit_payload(
            response=response,
            trace_events=trace_events,
            extra={"decision_record": decision_record} if decision_record is not None else None,
        ),
    )


def log_guarded_tool_result(audit_store: Any, *, result: dict[str, Any]) -> None:
    audit_store.log(
        session_id=str(result.get("session_id") or "default-session"),
        event_type="guarded_tool_call",
        risk_score=float(result.get("risk") or result.get("risk_score") or 0.0),
        payload=build_result_audit_payload(result=result),
    )


def log_action_decision(
    audit_store: Any,
    *,
    request: Any,
    response: Any,
    execution: Any,
    trace_events: list[dict[str, Any]],
    decision_record: Any = None,
) -> None:
    audit_store.log(
        session_id=_session_id(response),
        event_type="action_guard_decision",
        risk_score=_risk_score(response),
        payload=build_request_decision_audit_payload(
            request=request,
            decision=response,
            trace_events=trace_events,
            extra={
                "execution_key": _field(execution, "execution_key"),
                "tool_name": _field(execution, "tool_name"),
                "mapped_args": _field(execution, "mapped_args", {}),
                "execution_plan": _field(execution, "execution_plan"),
                "execution_report": _field(execution, "execution_report"),
                "lifecycle_report": _field(execution, "lifecycle_report"),
                "decision_record": decision_record,
            },
        ),
    )


def log_action_observation(
    audit_store: Any,
    *,
    request: Any,
    response: Any,
    trace_events: list[dict[str, Any]],
    decision_record: Any = None,
) -> None:
    dumped = audit_dump(response)
    output_analysis = dumped.get("output_analysis") if isinstance(dumped, dict) else {}
    audit_store.log(
        session_id=_session_id(response),
        event_type="action_guard_observation",
        risk_score=float(output_analysis.get("risk_score") or 0.0) if isinstance(output_analysis, dict) else 0.0,
        payload=build_request_decision_audit_payload(
            request=request,
            decision=response,
            trace_events=trace_events,
            extra={"decision_record": decision_record} if decision_record is not None else None,
        ),
    )


def log_proxy_result(audit_store: Any, *, flow: ProxyFlow, result: dict[str, Any]) -> None:
    audit_store.log(
        session_id=str(result.get("session_id") or "default-session"),
        event_type=_PROXY_EVENT_TYPES[flow],
        risk_score=float(result.get("risk_score") or 0.0),
        payload=build_result_audit_payload(result=result),
    )


def log_baseline_result(audit_store: Any, *, flow: BaselineFlow, result: dict[str, Any]) -> None:
    audit_store.log(
        session_id=str(result.get("session_id") or "default-session"),
        event_type=_BASELINE_EVENT_TYPES[flow],
        risk_score=_result_risk_score(result),
        payload=build_result_audit_payload(result=result),
    )
