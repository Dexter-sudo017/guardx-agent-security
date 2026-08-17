import os
from contextlib import contextmanager
from datetime import UTC, datetime
from time import perf_counter
from typing import Any
from uuid import uuid4

from app.audit.embedding_ablation_compare import deltas_vs_baseline, mode_case_comparison
from app.audit.embedding_ablation_summary import summarize_ablation_matrix
from app.services.experiment_model_matrix import run_model_matrix
from app.services.qwen3_online_bridge import reset_external_qwen3_worker


SCHEMA_VERSION = "guardx-embedding-ablation-v1"

EMBEDDING_ABLATION_MODES: dict[str, dict[str, bool]] = {
    "none": {"direct_embedding": False, "srtp_provider": False, "qwen3_online": False},
    "srtp_only": {"direct_embedding": False, "srtp_provider": True, "qwen3_online": False},
    "qwen3_only": {"direct_embedding": False, "srtp_provider": False, "qwen3_online": True},
    "both": {"direct_embedding": False, "srtp_provider": True, "qwen3_online": True},
}


@contextmanager
def _temporary_env(updates: dict[str, str]):
    previous = {key: os.environ.get(key) for key in updates}
    try:
        for key, value in updates.items():
            os.environ[key] = value
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _mode_env(mode: str) -> dict[str, str]:
    config = EMBEDDING_ABLATION_MODES[mode]
    return {
        "GUARDX_DIRECT_EMBEDDING_ENABLED": "1" if config["direct_embedding"] else "0",
        "GUARDX_RISK_PROVIDER_SRTP_EMBEDGUARD_ENABLED": "1" if config["srtp_provider"] else "0",
        "GUARDX_QWEN3_ONLINE": "1" if config["qwen3_online"] else "0",
    }


def run_embedding_ablation(
    *,
    suite_id: str = "guardx_contest_attack_probe",
    policy_profile: str = "v21",
    models: list[str] | None = None,
    modes: list[str] | None = None,
    base_session_id: str | None = None,
    seed: int = 1700,
) -> dict[str, Any]:
    active_models = [model.strip() for model in models or ["mock-safe-model"] if model.strip()] or ["mock-safe-model"]
    active_modes = [mode.strip() for mode in modes or list(EMBEDDING_ABLATION_MODES) if mode.strip()]
    unknown_modes = [mode for mode in active_modes if mode not in EMBEDDING_ABLATION_MODES]
    if unknown_modes:
        raise ValueError(f"Unknown embedding ablation modes: {', '.join(unknown_modes)}")

    run_id = base_session_id or f"embedding-ablation-{uuid4().hex[:8]}"
    mode_results: dict[str, dict[str, Any]] = {}
    summaries: dict[str, dict[str, Any]] = {}
    mode_configs: dict[str, dict[str, bool]] = {}

    for index, mode in enumerate(active_modes):
        env = _mode_env(mode)
        started = perf_counter()
        try:
            with _temporary_env(env):
                matrix = run_model_matrix(
                    suite_id=suite_id,
                    policy_profile=policy_profile,
                    models=active_models,
                    base_session_id=f"{run_id}-{mode}",
                    seed=seed + index,
                )
        finally:
            reset_external_qwen3_worker()
        elapsed_ms = round((perf_counter() - started) * 1000.0, 3)
        matrix["embedding_ablation"] = {
            "mode": mode,
            "config": EMBEDDING_ABLATION_MODES[mode],
            "env": env,
            "elapsed_ms": elapsed_ms,
        }
        summary = summarize_ablation_matrix(matrix, suite_id=suite_id)
        summary["elapsed_ms"] = elapsed_ms
        mode_results[mode] = matrix
        summaries[mode] = summary
        mode_configs[mode] = dict(EMBEDDING_ABLATION_MODES[mode])

    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "suite_id": suite_id,
        "policy_profile": policy_profile,
        "models": active_models,
        "modes": active_modes,
        "mode_configs": mode_configs,
        "created_at": datetime.now(UTC).isoformat(),
        "summaries": summaries,
        "deltas_vs_none": deltas_vs_baseline(summaries),
        "matrices": mode_results,
        "comparison": mode_case_comparison(mode_results),
    }
