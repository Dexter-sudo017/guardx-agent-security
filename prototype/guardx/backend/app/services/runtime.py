from importlib import import_module
from time import perf_counter, time

from app.services.action_observation_runtime import safe_observation_text as _safe_observation_text
from app.services.admin_runtime import (
    APP_ROOT,
    PROJECT_ROOT,
    STATIC_DASHBOARD,
    STATIC_EXPERIMENT_DASHBOARD,
    STATIC_GATEWAY,
    STATIC_INDEX,
    STATIC_LOGIN,
    STATIC_PORTAL,
    get_app,
    protected_html as _protected_html,
    set_app,
    web_access_allowed as _web_access_allowed,
    web_token as _web_token,
)
from app.services.baseline_runtime import (
    baseline_prompt as _baseline_prompt,
    baseline_tool_preview as _baseline_tool_preview,
)
from app.services.guarded_generation import (
    allowed_refusal_recovery as _allowed_refusal_recovery,
    apply_action as _apply_action,
    clean_context_snippet as _clean_context_snippet,
    generate_with_guard_fallback as _generate_with_guard_fallback,
    guarded_rag_prompt as _guarded_rag_prompt,
    is_refusal_like as _is_refusal_like,
    safe_model_unavailable_message as _safe_model_unavailable_message,
)
from app.services.guarded_risk_runtime import (
    maybe_merge_online_embedding as _maybe_merge_online_embedding,
    merge_risk_with_embedding_route as _merge_risk_with_embedding_route,
    recover_benign_vlm_visual_training as _recover_benign_vlm_visual_training,
)
from app.services.proxy_runtime import (
    ANYTHINGLLM_WORKSPACE_CONFIG,
    ANYTHINGLLM_WORKSPACE_EXAMPLE_CONFIG,
    anythingllm_context_for_workspace as _anythingllm_context_for_workspace,
    anythingllm_workspace_config as _anythingllm_workspace_config,
    blocking_action as _blocking_action,
    extract_answer_text as _extract_answer_text,
    forward_anythingllm as _forward_anythingllm,
    forward_json_target as _forward_json_target,
    require_proxy_token as _require_proxy_token,
)
from app.services.runtime_state import adapter_registry, audit_store
from app.services.security_runtime import (
    DEPLOYMENT_SECURITY_CONFIG,
    deployment_security_policy as _deployment_security_policy,
    rate_limit_key as _rate_limit_key,
    rate_limit_per_minute as _rate_limit_per_minute,
)


def _action_tool_mapping(surface: str, action: dict) -> tuple[str, dict]:
    normalize_action_to_tool = _lazy_symbol("normalize_action_to_tool")
    return normalize_action_to_tool(surface, action)


_LAZY_SYMBOLS = {
    "ActionGuardRequest": ("app.models", "ActionGuardRequest"),
    "ActionGuardResponse": ("app.models", "ActionGuardResponse"),
    "ActionObservationRequest": ("app.models", "ActionObservationRequest"),
    "ActionObservationResponse": ("app.models", "ActionObservationResponse"),
    "AnalysisResult": ("app.models", "AnalysisResult"),
    "GuardedChatRequest": ("app.models", "GuardedChatRequest"),
    "GuardedRagRequest": ("app.models", "GuardedRagRequest"),
    "GuardedResponse": ("app.models", "GuardedResponse"),
    "GuardedVlmOcrRequest": ("app.models", "GuardedVlmOcrRequest"),
    "ToolCallRequest": ("app.models", "ToolCallRequest"),
    "SETTINGS": ("app.config", "SETTINGS"),
    "chat_vlm_route_adapter": ("app.guards", "chat_vlm_route_adapter"),
    "context_guard": ("app.guards", "context_guard"),
    "embedding_guard": ("app.guards", "embedding_guard"),
    "embedding_guard_online": ("app.guards", "embedding_guard_online"),
    "external_calibration_adapter": ("app.guards", "external_calibration_adapter"),
    "input_guard": ("app.guards", "input_guard"),
    "output_guard": ("app.guards", "output_guard"),
    "rag_vlm_safe_frame_adapter": ("app.guards", "rag_vlm_safe_frame_adapter"),
    "review_fallback": ("app.guards", "review_fallback"),
    "safe_frame_adapter": ("app.guards", "safe_frame_adapter"),
    "segment_role_adapter": ("app.guards", "segment_role_adapter"),
    "segment_role_features": ("app.guards", "segment_role_features"),
    "zh_rag_safe_frame_adapter": ("app.guards", "zh_rag_safe_frame_adapter"),
    "rate_limit_state": ("app.middleware.state", "rate_limit_state"),
    "session_risk_state": ("app.middleware.state", "session_risk_state"),
    "decide_action": ("app.policy.engine", "decide_action"),
    "merge_risk": ("app.policy.engine", "merge_risk"),
    "next_session_risk": ("app.policy.engine", "next_session_risk"),
    "normalize_action_to_tool": ("app.executor", "normalize_action_to_tool"),
    "review_tool_call": ("app.sandbox.tools", "review_tool_call"),
    "list_presets": ("app.demo_presets", "list_presets"),
    "list_eval_suites": ("app.eval_presets", "list_eval_suites"),
    "run_benchmark_suite": ("app.eval_suite", "run_benchmark_suite"),
    "run_smoke_suite": ("app.eval_suite", "run_smoke_suite"),
    "runtime_summary": ("app.eval_suite", "runtime_summary"),
    "list_target_catalog": ("app.target_catalog", "list_target_catalog"),
    "load_target_profiles": ("app.target_profiles", "load_target_profiles"),
}


def _lazy_symbol(name: str):
    module_name, attr_name = _LAZY_SYMBOLS[name]
    value = getattr(import_module(module_name), attr_name)
    globals()[name] = value
    return value


def __getattr__(name: str):
    if name in _LAZY_SYMBOLS:
        return _lazy_symbol(name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "ANYTHINGLLM_WORKSPACE_CONFIG",
    "ANYTHINGLLM_WORKSPACE_EXAMPLE_CONFIG",
    "APP_ROOT",
    "DEPLOYMENT_SECURITY_CONFIG",
    "PROJECT_ROOT",
    "STATIC_DASHBOARD",
    "STATIC_EXPERIMENT_DASHBOARD",
    "STATIC_GATEWAY",
    "STATIC_INDEX",
    "STATIC_LOGIN",
    "STATIC_PORTAL",
    "_action_tool_mapping",
    "_allowed_refusal_recovery",
    "_anythingllm_context_for_workspace",
    "_anythingllm_workspace_config",
    "_apply_action",
    "_baseline_prompt",
    "_baseline_tool_preview",
    "_blocking_action",
    "_clean_context_snippet",
    "_deployment_security_policy",
    "_extract_answer_text",
    "_forward_anythingllm",
    "_forward_json_target",
    "_generate_with_guard_fallback",
    "_guarded_rag_prompt",
    "_is_refusal_like",
    "_maybe_merge_online_embedding",
    "_merge_risk_with_embedding_route",
    "_protected_html",
    "_rate_limit_key",
    "_rate_limit_per_minute",
    "_recover_benign_vlm_visual_training",
    "_require_proxy_token",
    "_safe_model_unavailable_message",
    "_safe_observation_text",
    "_web_access_allowed",
    "_web_token",
    "adapter_registry",
    "audit_store",
    "get_app",
    "perf_counter",
    "set_app",
    "time",
    *_LAZY_SYMBOLS,
]
