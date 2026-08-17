from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np

from app.guards import segment_role_features


PROJECT_ROOT = Path(__file__).resolve().parents[5]
POLICY_PATH = PROJECT_ROOT / "configs" / "embedding_guard_policy_qwen3_joint_online.json"

BYPASS_CUES = [
    "ignore",
    "despite",
    "bypass",
    "override",
    "忽略",
    "无视",
    "绕过",
    "即使",
]

FEATURE_NAMES = [
    *segment_role_features.ROLE_FEATURE_NAMES,
    "bypass_cue_count_log",
    "online_score",
    "online_raw_score",
    "online_threshold",
    "dual_safe_score",
    "dual_active_score",
    "dual_margin",
]


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
    adapter = external.get("segment_role_adapter", {})
    return dict(adapter) if isinstance(adapter, dict) else {}


def _sigmoid(value: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(value, -40.0, 40.0)))


def _bypass_count(text: str) -> float:
    lower = text.lower()
    return math.log1p(sum(1 for cue in BYPASS_CUES if cue in lower))


def _feature_dict(
    text: str,
    surface: str,
    online_metadata: dict[str, Any],
    segments: list[tuple[str, str]] | None,
) -> dict[str, float]:
    role = segment_role_features.extract_role_feature_dict(text, surface, segments)
    dual = dict(online_metadata.get("segment_aware_dual_head") or {})
    online_score = float(online_metadata.get("calibrated_probability", online_metadata.get("probability", 0.0)) or 0.0)
    online_raw = float(online_metadata.get("raw_probability", online_metadata.get("probability", 0.0)) or 0.0)
    online_threshold = float(online_metadata.get("effective_threshold", online_metadata.get("threshold", 0.554644)) or 0.554644)
    dual_safe = float(dual.get("safe_frame_score", 0.0) or 0.0)
    dual_active = float(dual.get("active_intent_score", 0.0) or 0.0)
    role.update(
        {
            "bypass_cue_count_log": _bypass_count(text),
            "online_score": online_score,
            "online_raw_score": online_raw,
            "online_threshold": online_threshold,
            "dual_safe_score": dual_safe,
            "dual_active_score": dual_active,
            "dual_margin": dual_active - dual_safe,
        }
    )
    return {name: float(role.get(name, 0.0)) for name in FEATURE_NAMES}


@dataclass(frozen=True)
class SegmentRoleAdapter:
    heads: list[str]
    weights: np.ndarray
    biases: np.ndarray
    feature_mean: np.ndarray
    feature_std: np.ndarray
    thresholds: dict[str, float]
    path: str

    def score(
        self,
        text: str,
        surface: str,
        online_metadata: dict[str, Any],
        segments: list[tuple[str, str]] | None,
    ) -> dict[str, float]:
        feature_dict = _feature_dict(text, surface, online_metadata, segments)
        x = np.asarray([[feature_dict[name] for name in FEATURE_NAMES]], dtype=np.float32)
        xs = ((x - self.feature_mean) / self.feature_std).astype(np.float32)
        scores = _sigmoid((xs @ self.weights.T) + self.biases.reshape(1, -1)).reshape(-1)
        return {head: float(score) for head, score in zip(self.heads, scores)}


@lru_cache(maxsize=8)
def load_adapter(policy_path: str | None = None) -> SegmentRoleAdapter | None:
    policy_path = policy_path or str(_policy_path_from_env())
    policy = _load_json(Path(policy_path))
    config = _config(policy)
    if not config.get("enabled", False):
        return None
    checkpoint = _resolve(str(config.get("checkpoint", "")))
    if not checkpoint.exists():
        return None
    loaded = np.load(checkpoint, allow_pickle=False)
    heads = [str(item) for item in loaded["heads"].tolist()]
    feature_names = [str(item) for item in loaded["feature_names"].tolist()]
    if feature_names != FEATURE_NAMES:
        return None
    threshold_values = loaded["thresholds"].astype(np.float32)
    thresholds = {head: float(value) for head, value in zip(heads, threshold_values)}
    for key, value in dict(config.get("thresholds", {})).items():
        if key in thresholds:
            thresholds[key] = float(value)
    if "bypass_threshold" in config:
        thresholds["bypass"] = float(config["bypass_threshold"])
    return SegmentRoleAdapter(
        heads=heads,
        weights=loaded["weights"].astype(np.float32),
        biases=loaded["biases"].astype(np.float32),
        feature_mean=loaded["feature_mean"].astype(np.float32),
        feature_std=loaded["feature_std"].astype(np.float32),
        thresholds=thresholds,
        path=str(checkpoint),
    )


def clear_cache() -> None:
    load_adapter.cache_clear()


def score_text(
    text: str,
    surface: str,
    online_metadata: dict[str, Any],
    labels: list[str],
    segments: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    adapter = load_adapter()
    if adapter is None:
        return {"enabled": False}
    policy = _load_json(_policy_path_from_env())
    config = _config(policy)
    raw_scores = adapter.score(text, surface, online_metadata, segments)
    active_heads = [str(item) for item in config.get("active_heads", ["bypass"])]
    head_payload = {}
    for head, score in raw_scores.items():
        threshold = float(adapter.thresholds.get(head, 0.5))
        head_payload[head] = {
            "score": round(score, 6),
            "threshold": round(threshold, 6),
            "is_positive": bool(score >= threshold),
        }
    return {
        "enabled": True,
        "heads": head_payload,
        "active_heads": active_heads,
        "is_bypass": bool(head_payload.get("bypass", {}).get("is_positive", False)),
        "bypass_score": head_payload.get("bypass", {}).get("score"),
        "path": adapter.path,
        "labels_seen": len(labels),
    }
