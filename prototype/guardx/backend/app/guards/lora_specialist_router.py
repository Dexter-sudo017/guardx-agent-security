from __future__ import annotations

import json
import os
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.guards import local_lora_provider
from app.models import AnalysisResult


PROJECT_ROOT = Path(__file__).resolve().parents[5]
PROFILE_PATH = PROJECT_ROOT / "configs" / "lora_specialist_routing_profile.json"
DEFAULT_LORA_300 = PROJECT_ROOT / "models" / "guardx-local-lora-semantic-classifier-gpu-300"
DEFAULT_LORA_500 = PROJECT_ROOT / "models" / "guardx-local-lora-semantic-classifier-gpu-500"

SURFACE_ALIASES = {
    "agent": "agent_tool",
    "agent action": "agent_tool",
    "agent_action": "agent_tool",
    "agent_tool": "agent_tool",
    "chat": "chat",
    "context": "rag",
    "input": "chat",
    "llm input": "chat",
    "llm_input": "chat",
    "multimodal": "vlm",
    "ocr": "vlm",
    "ocr/vlm": "vlm",
    "plugin": "agent_tool",
    "rag": "rag",
    "tool": "agent_tool",
    "tool-output": "agent_tool",
    "tool_output": "agent_tool",
    "vlm": "vlm",
    "vlm_ocr": "vlm",
}


@contextmanager
def _patched_env(updates: dict[str, str]):
    original = {key: os.environ.get(key) for key in updates}
    try:
        for key, value in updates.items():
            os.environ[key] = value
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@lru_cache(maxsize=1)
def load_routing_profile() -> dict[str, Any]:
    if not PROFILE_PATH.exists():
        return {
            "schema_version": "guardx-lora-specialist-routing-profile-v1",
            "specialist_candidates": [],
            "evaluation_plan": {"short_term": "local fallback profile"},
        }
    try:
        return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {
            "schema_version": "guardx-lora-specialist-routing-profile-v1",
            "specialist_candidates": [],
            "profile_error": "failed_to_load_profile",
        }


def _enabled() -> bool:
    return os.environ.get("GUARDX_LOCAL_LORA_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}


def _router_enabled() -> bool:
    return os.environ.get("GUARDX_LORA_SPECIALIST_ROUTER_ENABLED", "1").strip().lower() in {"1", "true", "yes", "on"}


def _canonical_surface(surface: str) -> str:
    normalized = str(surface or "chat").strip().lower()
    return SURFACE_ALIASES.get(normalized, normalized)


def _candidate_by_id(profile: dict[str, Any], candidate_id: str) -> dict[str, Any]:
    candidates = profile.get("specialist_candidates") if isinstance(profile.get("specialist_candidates"), list) else []
    for candidate in candidates:
        if isinstance(candidate, dict) and candidate.get("id") == candidate_id:
            return candidate
    return {}


def select_route(surface: str) -> dict[str, Any]:
    profile = load_routing_profile()
    canonical = _canonical_surface(surface)
    env_adapter = os.environ.get("GUARDX_LOCAL_LORA_ADAPTER_DIR")

    if env_adapter:
        return {
            "route_id": "env_override",
            "surface": canonical,
            "adapter_dir": env_adapter,
            "specialist_id": "env_override",
            "checkpoint_id": Path(env_adapter).name,
            "routing_rule": "explicit environment adapter override",
            "profile_schema": profile.get("schema_version"),
        }

    if canonical in {"rag", "agent_tool", "vlm"}:
        specialist_id = {
            "rag": "lora_rag_tool_agent",
            "agent_tool": "lora_rag_tool_agent",
            "vlm": "lora_vlm_ocr",
        }[canonical]
        candidate = _candidate_by_id(profile, specialist_id)
        configured_path = str(candidate.get("adapter_dir", "")).strip()
        adapter_dir = configured_path or str(DEFAULT_LORA_500)
        checkpoint_id = Path(adapter_dir).name
        return {
            "route_id": f"{specialist_id}_fallback_500" if not configured_path else specialist_id,
            "surface": canonical,
            "adapter_dir": adapter_dir,
            "specialist_id": specialist_id,
            "checkpoint_id": checkpoint_id,
            "routing_rule": candidate.get("routing_rule", "review signal; block requires runtime agreement"),
            "profile_schema": profile.get("schema_version"),
        }

    candidate = _candidate_by_id(profile, "lora_llm_input_harmful_request")
    configured_path = str(candidate.get("adapter_dir", "")).strip()
    adapter_dir = configured_path or str(DEFAULT_LORA_300)
    return {
        "route_id": "lora_llm_input_fallback_300" if not configured_path else "lora_llm_input_harmful_request",
        "surface": canonical,
        "adapter_dir": adapter_dir,
        "specialist_id": "lora_llm_input_harmful_request",
        "checkpoint_id": Path(adapter_dir).name,
        "routing_rule": candidate.get("routing_rule", "review signal; block requires runtime agreement"),
        "profile_schema": profile.get("schema_version"),
    }


_CURRENT_ADAPTER: str | None = None


def _clear_lora_cache_if_needed(adapter_dir: str) -> None:
    global _CURRENT_ADAPTER
    adapter_key = str(Path(adapter_dir).resolve())
    if _CURRENT_ADAPTER == adapter_key:
        return
    if hasattr(local_lora_provider._load_runtime, "cache_clear"):
        local_lora_provider._load_runtime.cache_clear()
    _CURRENT_ADAPTER = adapter_key


def analyze_text(text: str, surface: str = "input") -> AnalysisResult:
    if not _enabled() or not _router_enabled():
        return local_lora_provider.analyze_text(text, surface=surface)

    route = select_route(surface)
    adapter_dir = str(route["adapter_dir"])
    _clear_lora_cache_if_needed(adapter_dir)
    with _patched_env({"GUARDX_LOCAL_LORA_ADAPTER_DIR": adapter_dir}):
        result = local_lora_provider.analyze_text(text, surface=surface)

    metadata = {
        **(result.metadata or {}),
        "lora_specialist_router": {
            "enabled": True,
            "route_id": route["route_id"],
            "surface": route["surface"],
            "specialist_id": route["specialist_id"],
            "checkpoint_id": route["checkpoint_id"],
            "routing_rule": route["routing_rule"],
            "profile_schema": route["profile_schema"],
        },
    }
    labels = [*result.labels]
    if result.metadata.get("enabled"):
        labels.append(f"lora_route_{route['route_id']}")
    return AnalysisResult(
        risk_score=result.risk_score,
        labels=sorted(set(labels)),
        evidence=result.evidence,
        metadata=metadata,
    )
