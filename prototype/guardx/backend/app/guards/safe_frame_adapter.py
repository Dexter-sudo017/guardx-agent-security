from __future__ import annotations

import json
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


def _config(policy: dict[str, Any]) -> dict[str, Any]:
    external = dict(policy.get("external_calibration", {}))
    learned = external.get("learned_safe_frame_adapter", {})
    return dict(learned) if isinstance(learned, dict) else {}


@lru_cache(maxsize=1)
def load_adapter() -> base.CalibrationAdapter | None:
    policy = _load_json(POLICY_PATH)
    config = _config(policy)
    if not config.get("enabled", False):
        return None
    adapter_path = _resolve(str(config.get("adapter_path", "")))
    if not adapter_path.exists():
        return None
    loaded = np.load(adapter_path, allow_pickle=False)
    threshold = config.get("threshold")
    if threshold is None and config.get("results_json"):
        results_path = _resolve(str(config["results_json"]))
        if results_path.exists():
            results = _load_json(results_path)
            threshold = results.get("variants", {}).get("text", {}).get("threshold")
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


def score_text(text: str, surface: str) -> dict[str, Any]:
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
        "labels": [],
    }
    score = adapter.score(row)
    return {
        "enabled": True,
        "score": round(score, 6),
        "threshold": round(adapter.threshold, 6),
        "is_risky": bool(score >= adapter.threshold),
        "is_safe_frame": bool(score < adapter.threshold),
        "variant": adapter.variant,
        "path": adapter.path,
    }
