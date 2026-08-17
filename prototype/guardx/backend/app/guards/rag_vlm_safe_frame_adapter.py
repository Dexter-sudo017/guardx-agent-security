from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np

from app.guards import external_calibration_adapter as base


PROJECT_ROOT = Path(__file__).resolve().parents[5]
POLICY_PATH = PROJECT_ROOT / "configs" / "embedding_guard_policy_qwen3_joint_online.json"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _resolve(path: str) -> Path:
    item = Path(path)
    return item if item.is_absolute() else PROJECT_ROOT / item


def _policy_path_from_env() -> Path:
    override = os.environ.get("GUARDX_QWEN3_ONLINE_POLICY_PATH")
    return _resolve(override) if override else POLICY_PATH


def _config(policy: dict[str, Any]) -> dict[str, Any]:
    external = dict(policy.get("external_calibration", {}))
    adapter = external.get("rag_vlm_safe_frame_adapter", {})
    return dict(adapter) if isinstance(adapter, dict) else {}


@lru_cache(maxsize=8)
def load_adapter(policy_path: str | None = None) -> base.CalibrationAdapter | None:
    policy_path = policy_path or str(_policy_path_from_env())
    policy = _load_json(Path(policy_path))
    config = _config(policy)
    if not config.get("enabled", False):
        return None
    adapter_path = _resolve(str(config.get("adapter_path", "")))
    if not adapter_path.exists():
        return None
    loaded = np.load(adapter_path, allow_pickle=False)
    threshold = config.get("threshold")
    safe_threshold = config.get("safe_threshold")
    if (threshold is None or safe_threshold is None) and config.get("results_json"):
        results_path = _resolve(str(config["results_json"]))
        if results_path.exists():
            results = _load_json(results_path)
            threshold = results.get("threshold", threshold)
            safe_threshold = results.get("safe_threshold", safe_threshold)
    return base.CalibrationAdapter(
        variant=str(loaded["variant"].tolist()) if "variant" in loaded else "text",
        weights=loaded["weights"].astype(np.float32),
        bias=float(loaded["bias"].tolist()),
        numeric_mean=loaded["numeric_mean"].astype(np.float32) if "numeric_mean" in loaded else np.asarray([], dtype=np.float32),
        numeric_std=loaded["numeric_std"].astype(np.float32) if "numeric_std" in loaded else np.asarray([], dtype=np.float32),
        char_dim=int(loaded["char_dim"].tolist()),
        word_dim=int(loaded["word_dim"].tolist()),
        cat_dim=int(loaded["cat_dim"].tolist()),
        include_source_categories=bool(loaded["include_source_categories"].tolist()) if "include_source_categories" in loaded else False,
        include_source_metadata=bool(loaded["include_source_metadata"].tolist()) if "include_source_metadata" in loaded else False,
        threshold=float(threshold if threshold is not None else 0.5),
        path=str(adapter_path),
    )


def clear_cache() -> None:
    load_adapter.cache_clear()


def score_text(text: str, surface: str, online_metadata: dict[str, Any], labels: list[str]) -> dict[str, Any]:
    adapter = load_adapter()
    if adapter is None:
        return {"enabled": False}
    row = {
        "id": "runtime",
        "dataset": "runtime",
        "source": "runtime",
        "benchmark_family": "runtime",
        "category": "runtime",
        "surface": surface,
        "text": text,
        "text_length": len(text),
        "tokenish_length": len(text.split()),
        "online_score": online_metadata.get("calibrated_probability", online_metadata.get("probability", 0.0)),
        "online_probability": online_metadata.get("calibrated_probability", online_metadata.get("probability", 0.0)),
        "online_raw_probability": online_metadata.get("raw_probability", online_metadata.get("probability", 0.0)),
        "risk_score": online_metadata.get("calibrated_probability", online_metadata.get("probability", 0.0)),
        "embedding_risk": online_metadata.get("calibrated_probability", online_metadata.get("probability", 0.0)),
        "online_threshold": online_metadata.get("effective_threshold", online_metadata.get("threshold", 0.554644)),
        "online_surface_threshold": online_metadata.get("surface_threshold"),
        "online_block": bool(
            float(online_metadata.get("calibrated_probability", online_metadata.get("probability", 0.0)) or 0.0)
            >= float(online_metadata.get("effective_threshold", online_metadata.get("threshold", 0.554644)) or 0.554644)
        ),
        "labels": labels,
    }
    policy = _load_json(_policy_path_from_env())
    config = _config(policy)
    score = adapter.score(row)
    threshold = float(config.get("threshold", adapter.threshold))
    safe_threshold = float(config.get("safe_threshold", threshold))
    return {
        "enabled": True,
        "score": round(score, 6),
        "threshold": round(threshold, 6),
        "safe_threshold": round(safe_threshold, 6),
        "is_risky": bool(score >= threshold),
        "is_safe_frame": bool(score <= safe_threshold),
        "variant": adapter.variant,
        "path": adapter.path,
        "include_source_categories": adapter.include_source_categories,
        "include_source_metadata": adapter.include_source_metadata,
    }
