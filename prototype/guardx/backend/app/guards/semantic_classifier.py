from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from pathlib import Path

from app.models import AnalysisResult


TOKEN_RE = re.compile(r"[a-zA-Z0-9_\-']+")
PROJECT_ROOT = Path(__file__).resolve().parents[5]
MODEL_PATH = PROJECT_ROOT / "configs" / "semantic_risk_classifier.json"
CALIBRATION_PATH = PROJECT_ROOT / "configs" / "semantic_calibration_prototypes.json"
CALIBRATED_MODEL_PATH = PROJECT_ROOT / "configs" / "semantic_calibrated_ngram_model.json"


def _tokens(text: str) -> set[str]:
    return {match.group(0).lower() for match in TOKEN_RE.finditer(text)}


@lru_cache(maxsize=1)
def _load_model() -> dict:
    if not MODEL_PATH.exists():
        return {"enabled": False, "token_weights": {}, "bias": 0.0, "threshold": 0.12, "max_score": 0.18}
    try:
        return json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"enabled": False, "token_weights": {}, "bias": 0.0, "threshold": 0.12, "max_score": 0.18}


@lru_cache(maxsize=1)
def _load_calibration() -> dict:
    if not CALIBRATION_PATH.exists():
        return {"semantic_phrase_weights": [], "benign_phrase_weights": []}
    try:
        return json.loads(CALIBRATION_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"semantic_phrase_weights": [], "benign_phrase_weights": []}


@lru_cache(maxsize=1)
def _load_calibrated_ngram_model() -> dict:
    if not CALIBRATED_MODEL_PATH.exists():
        return {"enabled": False}
    try:
        return json.loads(CALIBRATED_MODEL_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"enabled": False}


def _phrase_hits(text: str, phrases: list[dict]) -> tuple[float, list[tuple[str, float, str]]]:
    lowered = text.lower()
    score = 0.0
    hits: list[tuple[str, float, str]] = []
    for item in phrases:
        if not isinstance(item, dict):
            continue
        phrase = str(item.get("phrase", "")).strip()
        if not phrase:
            continue
        if phrase.lower() in lowered:
            weight = float(item.get("weight", 0.0) or 0.0)
            label = str(item.get("label", "semantic_phrase_risk"))
            score += weight
            hits.append((phrase, weight, label))
    return score, hits


def _calibrated_ngram_score(text: str) -> tuple[float, list[tuple[str, float]], dict]:
    model = _load_calibrated_ngram_model()
    if not model.get("enabled", False):
        return 0.0, [], {"enabled": False}
    weights = model.get("feature_weights", {})
    ngram_min = int(model.get("ngram_min", 2))
    ngram_max = int(model.get("ngram_max", 5))
    raw = float(model.get("intercept", 0.0))
    hits: list[tuple[str, float]] = []
    lowered = text.lower()
    seen: set[str] = set()
    for n in range(ngram_min, ngram_max + 1):
        if len(lowered) < n:
            continue
        for index in range(0, len(lowered) - n + 1):
            token = lowered[index : index + n]
            if token in seen:
                continue
            seen.add(token)
            weight = float(weights.get(token, 0.0) or 0.0)
            if weight:
                raw += weight
                hits.append((token, weight))
    probability = 1.0 / (1.0 + math.exp(-max(min(raw, 20.0), -20.0)))
    threshold = float(model.get("threshold", 0.5))
    max_score = float(model.get("max_score", 0.22))
    if probability < threshold:
        return 0.0, hits, {
            "enabled": True,
            "probability": round(probability, 4),
            "threshold": threshold,
            "feature_hit_count": len(hits),
            "model_version": model.get("schema_version", "unknown"),
        }
    score = min(max_score, max(0.0, (probability - threshold) / max(0.001, 1.0 - threshold) * max_score))
    return round(score, 4), hits, {
        "enabled": True,
        "probability": round(probability, 4),
        "threshold": threshold,
        "feature_hit_count": len(hits),
        "model_version": model.get("schema_version", "unknown"),
        "run_id": model.get("run_id"),
    }


def analyze_text(text: str, surface: str = "input") -> AnalysisResult:
    model = _load_model()
    if not model.get("enabled", False):
        return AnalysisResult(risk_score=0.0, labels=[], evidence=[], metadata={"surface": surface, "classifier_enabled": False})

    tokens = _tokens(text)
    weights = model.get("token_weights", {})
    raw_score = float(model.get("bias", 0.0))
    hits: list[tuple[str, float]] = []
    for token in tokens:
        weight = float(weights.get(token, 0.0))
        if weight:
            raw_score += weight
            hits.append((token, weight))

    calibration = _load_calibration()
    phrase_score, phrase_hits = _phrase_hits(text, list(calibration.get("semantic_phrase_weights", [])))
    benign_phrase_score, benign_phrase_hits = _phrase_hits(text, list(calibration.get("benign_phrase_weights", [])))
    raw_score += phrase_score + benign_phrase_score
    ngram_score, ngram_hits, ngram_metadata = _calibrated_ngram_score(text)

    probability = 1.0 / (1.0 + math.exp(-max(min(raw_score, 20.0), -20.0)))
    threshold = float(model.get("threshold", 0.12))
    max_score = float(model.get("max_score", 0.18))
    if not hits and not phrase_hits and not ngram_score:
        return AnalysisResult(
            risk_score=0.0,
            labels=[],
            evidence=[],
            metadata={
                "surface": surface,
                "classifier_enabled": True,
                "semantic_probability": round(probability, 4),
                "threshold": threshold,
                "phrase_hit_count": len(phrase_hits),
                "benign_phrase_hit_count": len(benign_phrase_hits),
                "calibrated_ngram": ngram_metadata,
            },
        )

    top_hits = sorted(hits, key=lambda item: abs(item[1]), reverse=True)[:5]
    probability_score = max(0.0, (probability - threshold) * max_score)
    phrase_positive_score = max(0.0, sum(weight for _, weight, _ in phrase_hits if weight > 0)) * 0.36
    score = min(max(max_score, 0.22), max(probability_score, phrase_positive_score, ngram_score))
    phrase_labels = sorted({label for _, weight, label in phrase_hits if weight > 0})
    benign_labels = sorted({label for _, weight, label in benign_phrase_hits if weight < 0})
    ngram_labels = ["calibrated_ngram_semantic_risk"] if ngram_score > 0 else []
    top_ngram_hits = sorted(ngram_hits, key=lambda item: abs(item[1]), reverse=True)[:5]
    return AnalysisResult(
        risk_score=round(score, 4),
        labels=sorted(set(["trained_semantic_risk"] + phrase_labels + benign_labels + ngram_labels)),
        evidence=[f"{token}:{weight:.3f}" for token, weight in top_hits]
        + [f"phrase={phrase}:{weight:.3f}" for phrase, weight, _ in phrase_hits[:5]]
        + [f"benign_phrase={phrase}:{weight:.3f}" for phrase, weight, _ in benign_phrase_hits[:5]]
        + [f"ngram={token}:{weight:.3f}" for token, weight in top_ngram_hits],
        metadata={
            "surface": surface,
            "classifier_enabled": True,
            "semantic_probability": round(probability, 4),
            "threshold": threshold,
            "phrase_hit_count": len(phrase_hits),
            "benign_phrase_hit_count": len(benign_phrase_hits),
            "calibrated_ngram": ngram_metadata,
            "model_version": model.get("schema_version", "unknown"),
        },
    )
