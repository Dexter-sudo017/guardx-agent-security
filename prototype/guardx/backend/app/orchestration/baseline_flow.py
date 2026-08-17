from typing import Any

from app.config import SETTINGS
from app.guards import output_guard
from app.models import GuardedChatRequest, GuardedRagRequest, ToolCallRequest
from app.services.baseline_runtime import baseline_prompt, baseline_tool_preview
from app.services.runtime_state import adapter_registry


REFUSAL_MARKERS = (
    "i'm sorry",
    "i am sorry",
    "i can't",
    "i cannot",
    "unable to comply",
    "cannot comply",
)


def baseline_refused(answer: str) -> bool:
    lowered = answer.lower()
    return any(marker in lowered for marker in REFUSAL_MARKERS)


def run_baseline_chat(
    *,
    session_id: str,
    model: str,
    message: str,
    history: list[dict[str, str]],
    adapter: Any,
) -> dict[str, Any]:
    answer = adapter.generate(baseline_prompt(message), history, model)
    output_analysis = output_guard.analyze(answer)
    return {
        "session_id": session_id,
        "model": model,
        "mode": "baseline_chat",
        "answer": answer,
        "refused": baseline_refused(answer),
        "output_analysis": output_analysis.model_dump(),
        "note": "Direct baseline path without GuardX input, context, or output controls.",
    }


def run_baseline_rag_chat(
    *,
    session_id: str,
    model: str,
    message: str,
    history: list[dict[str, str]],
    context_chunks: list[str],
    adapter: Any,
) -> dict[str, Any]:
    answer = adapter.generate(baseline_prompt(message, context_chunks), history, model)
    output_analysis = output_guard.analyze(answer)
    return {
        "session_id": session_id,
        "model": model,
        "mode": "baseline_rag_chat",
        "answer": answer,
        "refused": False,
        "context_chunks": context_chunks,
        "output_analysis": output_analysis.model_dump(),
        "note": "Direct baseline path that concatenates untrusted retrieval context without GuardX context isolation.",
    }


def run_baseline_tool_call(
    *,
    session_id: str,
    tool_name: str,
    args: dict[str, Any],
    risk_hint: float | None,
) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "tool_name": tool_name,
        "risk": risk_hint,
        "decision": {
            "allowed": True,
            "mode": "allow",
            "reason": "Baseline target has no GuardX sandbox review.",
            "sanitized_args": args,
        },
        "preview": baseline_tool_preview(tool_name, args),
        "note": "Direct baseline path without GuardX tool policy.",
    }


def run_baseline_chat_route_flow(request: GuardedChatRequest) -> dict[str, Any]:
    model = request.model or SETTINGS.default_model
    return run_baseline_chat(
        session_id=request.session_id,
        model=model,
        message=request.message,
        history=request.history,
        adapter=adapter_registry.get(model),
    )


def run_baseline_rag_route_flow(request: GuardedRagRequest) -> dict[str, Any]:
    model = request.model or SETTINGS.default_model
    return run_baseline_rag_chat(
        session_id=request.session_id,
        model=model,
        message=request.message,
        history=request.history,
        context_chunks=request.context_chunks,
        adapter=adapter_registry.get(model),
    )


def run_baseline_tool_route_flow(request: ToolCallRequest) -> dict[str, Any]:
    return run_baseline_tool_call(
        session_id=request.session_id,
        tool_name=request.tool_name,
        args=request.args,
        risk_hint=request.risk_hint,
    )
