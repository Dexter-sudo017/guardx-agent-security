import json
import os
from datetime import UTC, datetime
from pathlib import Path

from app.adapters.registry import AdapterRegistry


BACKEND_ROOT = Path(__file__).resolve().parents[2]
LATEST_REAL_MODEL_GATE = BACKEND_ROOT / "data" / "experiment_runs" / "latest_real_model_gate.json"
MODEL_GROUPS = {
    "domestic": ["kimi-cn-k2_5", "zai-glm-4_5v", "dashscope-qwen-plus", "deepseek-openai-compatible"],
    "router": ["fourrouter-claude", "fourrouter-gpt"],
    "router_full": ["fourrouter-claude", "fourrouter-gemini", "fourrouter-gpt"],
    "local": ["mock-safe-model", "local-ollama"],
}
MODEL_GROUPS["all"] = [*MODEL_GROUPS["domestic"], *MODEL_GROUPS["router"]]
MODEL_GROUPS["real_candidates"] = [*MODEL_GROUPS["domestic"], "fourrouter-claude"]
DEFAULT_REAL_MODEL_SUITES = [
    "guardx_redteam_core",
    "guardx_false_positive_probe",
    "guardx_stability_probe",
    "guardx_contest_attack_probe",
    "guardx_public_benchmark_style_probe",
]
KEY_HANDLING_NOTE = "API keys are read only from process environment or GitHub Secrets and are never written to artifacts."


def safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in value)[:96] or "run"


def split_csv(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def recommended_from_gate(gate_path: Path | None = None) -> list[str]:
    gate_path = gate_path or LATEST_REAL_MODEL_GATE
    if not gate_path.exists():
        return []
    try:
        gate = json.loads(gate_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [str(item) for item in gate.get("recommended_models", []) if str(item).strip()]


def configured_real_candidates() -> list[str]:
    configured = {item.name for item in AdapterRegistry().list_models() if item.configured}
    return [model for model in MODEL_GROUPS["real_candidates"] if model in configured]


def expand_model_name(name: str, *, gate_path: Path | None = None) -> list[str]:
    if name == "auto":
        return recommended_from_gate(gate_path) or configured_real_candidates() or ["mock-safe-model"]
    return MODEL_GROUPS.get(name, [name])


def select_models(raw: str, *, only_configured: bool, gate_path: Path | None = None) -> list[str]:
    requested: list[str] = []
    for item in split_csv(raw):
        requested.extend(expand_model_name(item, gate_path=gate_path))
    deduped = list(dict.fromkeys(requested or ["mock-safe-model"]))
    if not only_configured:
        return deduped
    configured = {item.name for item in AdapterRegistry().list_models() if item.configured}
    return [model for model in deduped if model in configured] or ["mock-safe-model"]


def missing_env_for_model(registry: AdapterRegistry, model: str) -> list[str]:
    spec = registry.get_spec(model)
    if spec.get("type") != "openai_compatible":
        return []
    missing = []
    base_url_env = spec.get("base_url_env")
    api_key_env = spec.get("api_key_env")
    if base_url_env and not spec.get("base_url") and not os.getenv(str(base_url_env)):
        missing.append(str(base_url_env))
    if api_key_env and not spec.get("api_key") and not os.getenv(str(api_key_env)):
        missing.append(str(api_key_env))
    return missing


def configured_real_models(raw_models: str, *, include_local: bool = False, gate_path: Path | None = None) -> tuple[list[str], dict[str, list[str]]]:
    registry = AdapterRegistry()
    requested = select_models(raw_models, only_configured=False, gate_path=gate_path)
    if "auto" in split_csv(raw_models) and requested == ["mock-safe-model"]:
        requested = MODEL_GROUPS["real_candidates"]
    selected: list[str] = []
    missing_env: dict[str, list[str]] = {}
    for model in requested:
        spec = registry.get_spec(model)
        if not spec:
            missing_env[model] = ["model_not_registered"]
            continue
        adapter_type = str(spec.get("type", "unknown"))
        if adapter_type == "mock":
            continue
        if adapter_type == "ollama":
            info = registry.get_info(model)
            if include_local and info.configured:
                selected.append(model)
            else:
                missing_env[model] = ["local_ollama_unavailable"]
            continue
        if adapter_type == "openai_compatible" and not missing_env_for_model(registry, model):
            selected.append(model)
        else:
            missing_env[model] = missing_env_for_model(registry, model) or ["adapter_not_configured"]
    return list(dict.fromkeys(selected)), missing_env


def requested_models_for_skip(raw_models: str, missing_env: dict[str, list[str]], *, gate_path: Path | None = None) -> list[str]:
    if "auto" in split_csv(raw_models) and missing_env:
        return list(missing_env)
    return select_models(raw_models, only_configured=False, gate_path=gate_path)


def requested_models_for_report(raw_models: str, selected: list[str], missing_env: dict[str, list[str]]) -> list[str]:
    if "auto" in split_csv(raw_models):
        requested = [*selected, *missing_env]
        return list(dict.fromkeys(requested)) or MODEL_GROUPS["real_candidates"]
    return select_models(raw_models, only_configured=False)


def build_real_model_matrix_plan(
    *,
    run_id: str,
    raw_models: str = "auto",
    suites: list[str] | None = None,
    profile: str = "v5l",
    include_local: bool = False,
    gate_path: Path | None = None,
) -> dict:
    suites = suites or DEFAULT_REAL_MODEL_SUITES
    models, missing_env = configured_real_models(raw_models, include_local=include_local, gate_path=gate_path)
    return {
        "schema_version": "guardx-real-model-matrix-plan-v1",
        "run_id": run_id,
        "dry_run": True,
        "profile": profile,
        "requested_models": requested_models_for_report(raw_models, models, missing_env),
        "configured_models": models,
        "suites": suites,
        "missing_env": missing_env,
        "created_at": datetime.now(UTC).isoformat(),
        "key_handling": KEY_HANDLING_NOTE,
    }
