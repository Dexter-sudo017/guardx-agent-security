from typing import Any


def audit_dump(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if isinstance(value, dict):
        return {str(key): audit_dump(item) for key, item in value.items()}
    if isinstance(value, list):
        return [audit_dump(item) for item in value]
    if isinstance(value, tuple):
        return [audit_dump(item) for item in value]
    return value


def build_response_audit_payload(
    *,
    response: Any,
    trace_events: list[dict[str, Any]],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = audit_dump(response)
    if not isinstance(payload, dict):
        payload = {"response": payload}
    payload.update(audit_dump(extra or {}))
    payload["trace_events"] = audit_dump(trace_events)
    return payload


def build_request_decision_audit_payload(
    *,
    request: Any,
    decision: Any,
    trace_events: list[dict[str, Any]],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "request": audit_dump(request),
        "decision": audit_dump(decision),
    }
    payload.update(audit_dump(extra or {}))
    payload["trace_events"] = audit_dump(trace_events)
    return payload


def build_result_audit_payload(
    *,
    result: dict[str, Any],
    trace_events: list[dict[str, Any]] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = audit_dump(result)
    payload.update(audit_dump(extra or {}))
    if trace_events is not None:
        payload["trace_events"] = audit_dump(trace_events)
    return payload
