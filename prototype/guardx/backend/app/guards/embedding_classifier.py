from __future__ import annotations

import hashlib
import json
import math
import re
from functools import lru_cache
from pathlib import Path

from app.models import AnalysisResult


PROJECT_ROOT = Path(__file__).resolve().parents[5]
MODEL_PATH = PROJECT_ROOT / "configs" / "embedding_risk_classifier.json"
CALIBRATION_PATH = PROJECT_ROOT / "configs" / "semantic_calibration_prototypes.json"
WORD_RE = re.compile(r"[a-zA-Z0-9_\-']+")


def _normalize(text: str) -> str:
    words = WORD_RE.findall(text.lower())
    if words:
        return " ".join(words)
    return " ".join(text.lower().split())


def _hash_ngram(ngram: str, dims: int) -> int:
    digest = hashlib.blake2b(ngram.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % dims


def _vectorize(text: str, dims: int, ngram_min: int, ngram_max: int) -> dict[int, float]:
    normalized = _normalize(text)
    compact = normalized.replace(" ", "")
    vector: dict[int, float] = {}
    for source, weight in ((normalized, 1.0), (compact, 0.65)):
        if not source:
            continue
        for n in range(ngram_min, ngram_max + 1):
            if len(source) < n:
                continue
            for index in range(0, len(source) - n + 1):
                bucket = _hash_ngram(source[index : index + n], dims)
                vector[bucket] = vector.get(bucket, 0.0) + weight
    norm = math.sqrt(sum(value * value for value in vector.values()))
    if not norm:
        return {}
    return {key: value / norm for key, value in vector.items()}


def _cosine(left: dict[int, float], right: dict[int, float]) -> float:
    if not left or not right:
        return 0.0
    if len(left) > len(right):
        left, right = right, left
    return sum(value * right.get(key, 0.0) for key, value in left.items())


@lru_cache(maxsize=1)
def _load_model() -> dict:
    if not MODEL_PATH.exists():
        return {"enabled": False}
    try:
        return json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"enabled": False}


@lru_cache(maxsize=1)
def _load_calibration() -> dict:
    if not CALIBRATION_PATH.exists():
        return {"embedding_prototypes": []}
    try:
        return json.loads(CALIBRATION_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"embedding_prototypes": []}


@lru_cache(maxsize=1)
def _prototype_vectors() -> tuple[dict, list[tuple[dict, dict[int, float]]], list[tuple[dict, dict[int, float]]]]:
    model = _load_model()
    if not model.get("enabled", False):
        return model, [], []
    dims = int(model.get("dims", 512))
    ngram_min = int(model.get("ngram_min", 3))
    ngram_max = int(model.get("ngram_max", 5))
    risky: list[tuple[dict, dict[int, float]]] = []
    benign: list[tuple[dict, dict[int, float]]] = []
    calibration = _load_calibration()
    prototypes = list(model.get("prototypes", [])) + list(calibration.get("embedding_prototypes", []))
    for item in prototypes:
        if not isinstance(item, dict):
            continue
        vector = _vectorize(str(item.get("text", "")), dims, ngram_min, ngram_max)
        if not vector:
            continue
        if item.get("label") == "risky":
            risky.append((item, vector))
        elif item.get("label") == "benign":
            benign.append((item, vector))
    model = dict(model)
    model["calibration_prototype_count"] = len(calibration.get("embedding_prototypes", []))
    return model, risky, benign


def analyze_text(text: str, surface: str = "input") -> AnalysisResult:
    model, risky, benign = _prototype_vectors()
    if not model.get("enabled", False):
        return AnalysisResult(
            risk_score=0.0,
            labels=[],
            evidence=[],
            metadata={"surface": surface, "embedding_classifier_enabled": False},
        )

    dims = int(model.get("dims", 512))
    ngram_min = int(model.get("ngram_min", 3))
    ngram_max = int(model.get("ngram_max", 5))
    query = _vectorize(text, dims, ngram_min, ngram_max)
    risky_scores = [(_cosine(query, vector), item) for item, vector in risky]
    benign_scores = [(_cosine(query, vector), item) for item, vector in benign]
    best_risky = max(risky_scores, key=lambda item: item[0], default=(0.0, {}))
    best_benign = max(benign_scores, key=lambda item: item[0], default=(0.0, {}))

    threshold = float(model.get("threshold", 0.62))
    margin = float(model.get("margin", 0.07))
    max_score = float(model.get("max_score", 0.16))
    risky_similarity = float(best_risky[0])
    benign_similarity = float(best_benign[0])
    metadata = {
        "surface": surface,
        "embedding_classifier_enabled": True,
        "risky_similarity": round(risky_similarity, 4),
        "benign_similarity": round(benign_similarity, 4),
        "threshold": threshold,
        "margin": margin,
        "calibration_prototype_count": int(model.get("calibration_prototype_count", 0) or 0),
    }
    if risky_similarity < threshold or (risky_similarity - benign_similarity) < margin:
        return AnalysisResult(risk_score=0.0, labels=[], evidence=[], metadata=metadata)

    strength = min(1.0, (risky_similarity - threshold + margin) / max(0.001, 1.0 - threshold))
    score = round(max_score * strength, 4)
    case_id = best_risky[1].get("case_id", "unknown")
    family = best_risky[1].get("family", "unknown")
    return AnalysisResult(
        risk_score=score,
        labels=["embedding_semantic_risk"],
        evidence=[f"nearest_risky={case_id}", f"family={family}", f"similarity={risky_similarity:.3f}"],
        metadata=metadata | {"nearest_risky_case": case_id, "nearest_risky_family": family},
    )
