from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[5]
POLICY_PATH = PROJECT_ROOT / "configs" / "embedding_guard_policy_qwen3_joint_online.json"
_WORD_RE = re.compile(r"(?u)\b\w+\b")


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _resolve(path: str) -> Path:
    item = Path(path)
    return item if item.is_absolute() else PROJECT_ROOT / item


def _stable_index(value: str, dim: int) -> int:
    digest = hashlib.blake2b(value.encode("utf-8", errors="ignore"), digest_size=8).digest()
    return int.from_bytes(digest, "little", signed=False) % dim


def _add_hash(vec: np.ndarray, value: str, offset: int, dim: int, weight: float = 1.0) -> None:
    vec[offset + _stable_index(value, dim)] += weight


def _as_float(row: dict[str, Any], *keys: str, default: float = 0.0) -> float:
    for key in keys:
        value = row.get(key)
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return default


def _as_labels(row: dict[str, Any]) -> list[str]:
    labels = row.get("labels", row.get("embedding_labels", []))
    if isinstance(labels, str):
        return [labels]
    if isinstance(labels, list):
        return [str(label) for label in labels]
    return []


def _surface_flags(row: dict[str, Any]) -> tuple[float, float, float, float]:
    surface = str(row.get("surface", ""))
    return (
        float(surface == "chat" or surface == "default"),
        float(surface == "rag"),
        float(surface == "vlm_ocr"),
        float(surface == "agent_tool"),
    )


def _score_numeric_row(row: dict[str, Any]) -> list[float]:
    return [
        _as_float(row, "online_score", "online_probability"),
        _as_float(row, "online_threshold", default=0.554644),
    ]


def _risk_metadata_numeric_row(row: dict[str, Any]) -> list[float]:
    labels = set(_as_labels(row))
    return [
        _as_float(row, "online_raw_probability", "online_probability", "online_score"),
        _as_float(row, "online_base_probability", "online_probability", "online_score"),
        _as_float(row, "online_avg_cosine_to_clean", default=0.0),
        _as_float(row, "risk_score", "embedding_risk", "online_score"),
        _as_float(row, "embedding_risk", "risk_score", "online_score"),
        _as_float(row, "online_surface_threshold", "online_threshold", default=0.554644),
        float(bool(row.get("online_block"))),
        float("embedding_jailbreak_risk" in labels),
        float("embedding_jailbreak_suspicious" in labels),
        float("qwen3_joint_online" in labels),
        float(len(labels)),
    ]


def _metadata_numeric_row(row: dict[str, Any], include_source_metadata: bool) -> list[float]:
    text_length = float(row.get("text_length") or 0.0)
    tokenish_length = float(row.get("tokenish_length") or 0.0)
    source = str(row.get("source", "")).lower()
    benchmark = str(row.get("benchmark_family", "")).lower()
    chat, rag, vlm_ocr, agent_tool = _surface_flags(row)
    source_features = [
        float(source.startswith("jailbreakbench")),
        float("harmbench" in source or "harmbench" in benchmark),
        float("advbench" in source or "advbench" in benchmark),
    ] if include_source_metadata else [0.0, 0.0, 0.0]
    return [
        text_length,
        tokenish_length,
        text_length / max(1.0, tokenish_length),
        *source_features,
        chat,
        rag,
        vlm_ocr,
        agent_tool,
    ]


def _numeric(row: dict[str, Any], include_source_metadata: bool) -> np.ndarray:
    values = _score_numeric_row(row)
    values.extend(_risk_metadata_numeric_row(row))
    values.extend(_metadata_numeric_row(row, include_source_metadata=include_source_metadata))
    return np.asarray([values], dtype=np.float32)


def _text_matrix(row: dict[str, Any], char_dim: int, word_dim: int, cat_dim: int, include_source_categories: bool) -> np.ndarray:
    total_dim = char_dim + word_dim + cat_dim
    matrix = np.zeros((1, total_dim), dtype=np.float32)
    vec = matrix[0]
    text = str(row.get("text", "")).lower()
    padded = f" {text} "
    for n in (3, 4, 5):
        if len(padded) >= n:
            for idx in range(0, len(padded) - n + 1):
                gram = padded[idx : idx + n]
                if gram.strip():
                    _add_hash(vec, f"c{n}:{gram}", 0, char_dim)
    words = _WORD_RE.findall(text)
    for word in words:
        _add_hash(vec, f"w:{word}", char_dim, word_dim)
    for left, right in zip(words, words[1:]):
        _add_hash(vec, f"b:{left}_{right}", char_dim, word_dim)
    category_keys = ("surface",) if not include_source_categories else ("source", "benchmark_family", "category", "surface")
    cat_offset = char_dim + word_dim
    for key in category_keys:
        _add_hash(vec, f"{key}:{row.get(key, '')}", cat_offset, cat_dim)
    norm = float(np.linalg.norm(vec))
    if norm > 0:
        vec /= norm
    return matrix


def _scale_apply(matrix: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    return ((matrix - mean) / std).astype(np.float32)


def _sigmoid(value: float) -> float:
    value = max(-50.0, min(50.0, value))
    return float(1.0 / (1.0 + np.exp(-value)))


@dataclass(frozen=True)
class CalibrationAdapter:
    variant: str
    weights: np.ndarray
    bias: float
    numeric_mean: np.ndarray
    numeric_std: np.ndarray
    char_dim: int
    word_dim: int
    cat_dim: int
    include_source_categories: bool
    include_source_metadata: bool
    threshold: float
    path: str

    def score(self, row: dict[str, Any]) -> float:
        parts: list[np.ndarray] = []
        if self.variant in {"score", "full"}:
            parts.append(_scale_apply(_numeric(row, include_source_metadata=self.include_source_metadata), self.numeric_mean, self.numeric_std))
        if self.variant in {"text", "full"}:
            parts.append(_text_matrix(row, self.char_dim, self.word_dim, self.cat_dim, self.include_source_categories))
        features = np.hstack(parts).astype(np.float32)
        logit = (features @ self.weights.reshape(-1, 1)).reshape(-1)[0] + self.bias
        return _sigmoid(float(logit))


def _adapter_config(policy: dict[str, Any]) -> dict[str, Any]:
    config = dict(policy.get("external_calibration", {}))
    return config


@lru_cache(maxsize=1)
def load_adapter() -> CalibrationAdapter | None:
    policy = _load_json(POLICY_PATH)
    config = _adapter_config(policy)
    if not config.get("enabled", False):
        return None
    adapter_path = _resolve(str(config.get("adapter_path", "")))
    if not adapter_path.exists():
        return None
    loaded = np.load(adapter_path, allow_pickle=False)
    results_threshold = config.get("threshold")
    if results_threshold is None and config.get("results_json"):
        results_path = _resolve(str(config["results_json"]))
        if results_path.exists():
            results = _load_json(results_path)
            variant = str(config.get("variant", "mixed_full"))
            results_threshold = results.get("variants", {}).get(variant, {}).get("threshold")
    threshold = float(results_threshold if results_threshold is not None else 0.5)
    return CalibrationAdapter(
        variant=str(loaded["variant"].tolist()) if "variant" in loaded else "full",
        weights=loaded["weights"].astype(np.float32),
        bias=float(loaded["bias"].tolist()),
        numeric_mean=loaded["numeric_mean"].astype(np.float32),
        numeric_std=loaded["numeric_std"].astype(np.float32),
        char_dim=int(loaded["char_dim"].tolist()),
        word_dim=int(loaded["word_dim"].tolist()),
        cat_dim=int(loaded["cat_dim"].tolist()),
        include_source_categories=bool(loaded["include_source_categories"].tolist()) if "include_source_categories" in loaded else True,
        include_source_metadata=bool(loaded["include_source_metadata"].tolist()) if "include_source_metadata" in loaded else True,
        threshold=threshold,
        path=str(adapter_path),
    )


def clear_cache() -> None:
    load_adapter.cache_clear()


def score_text(text: str, surface: str, online_metadata: dict[str, Any], labels: list[str]) -> dict[str, Any]:
    adapter = load_adapter()
    if adapter is None:
        return {"enabled": False}
    base_samples = online_metadata.get("base_probability_samples") or []
    try:
        base_probability = sum(float(item) for item in base_samples) / len(base_samples) if base_samples else None
    except (TypeError, ValueError):
        base_probability = None
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
        "online_base_probability": base_probability,
        "online_avg_cosine_to_clean": online_metadata.get("avg_cosine_to_clean"),
        "risk_score": online_metadata.get("calibrated_probability", online_metadata.get("probability", 0.0)),
        "embedding_risk": online_metadata.get("calibrated_probability", online_metadata.get("probability", 0.0)),
        "online_threshold": online_metadata.get("effective_threshold", online_metadata.get("threshold", 0.554644)),
        "online_surface_threshold": online_metadata.get("surface_threshold"),
        "online_block": bool(float(online_metadata.get("calibrated_probability", online_metadata.get("probability", 0.0)) or 0.0) >= float(online_metadata.get("effective_threshold", online_metadata.get("threshold", 0.554644)) or 0.554644)),
        "labels": labels,
    }
    score = adapter.score(row)
    return {
        "enabled": True,
        "score": round(score, 6),
        "threshold": round(adapter.threshold, 6),
        "variant": adapter.variant,
        "path": adapter.path,
        "include_source_categories": adapter.include_source_categories,
        "include_source_metadata": adapter.include_source_metadata,
    }
