from __future__ import annotations

import json
import math
import random
import re
from hashlib import sha256
from functools import lru_cache
from pathlib import Path

from app.models import AnalysisResult, Message


PROJECT_ROOT = Path(__file__).resolve().parents[5]
POLICY_PATH = PROJECT_ROOT / "configs" / "embedding_guard_policy.json"
DEFAULT_MODEL_PATH = PROJECT_ROOT / "configs" / "embedding_guard_model.json"
TOKEN_RE = re.compile(r"[a-zA-Z0-9_\-']+|[\u4e00-\u9fff]")


DEFAULT_POLICY = {
    "enabled": True,
    "model_path": "configs/embedding_guard_model.json",
    "embedding_backend": {
        "type": "hash",
        "cache_path": "evaluation/srtp_embedguard/embeddings_full_supported_stable_random.json",
        "srtp_root": "third_party/eaas-privacy-master",
        "notes": "Use hash for portable GuardX prototype; switch to srtp when torch/transformers checkpoints are available.",
    },
    "embedding_dim": 256,
    "risk_weight": 0.22,
    "medium_threshold": 0.45,
    "high_threshold": 0.7,
    "dp": {"enabled": True, "noise_std": 0.035, "samples": 5, "denoise_blend": 0.82},
    "soft_prompt": {"enabled": True, "scale": 0.18},
}


def _load_json(path: Path, fallback: dict) -> dict:
    if not path.exists():
        return fallback
    try:
        loaded = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return fallback
    merged = fallback.copy()
    merged.update({key: value for key, value in loaded.items() if key != "schema_version"})
    if isinstance(fallback.get("dp"), dict):
        merged["dp"] = {**fallback["dp"], **dict(loaded.get("dp", {}))}
    if isinstance(fallback.get("soft_prompt"), dict):
        merged["soft_prompt"] = {**fallback["soft_prompt"], **dict(loaded.get("soft_prompt", {}))}
    if isinstance(fallback.get("embedding_backend"), dict):
        merged["embedding_backend"] = {**fallback["embedding_backend"], **dict(loaded.get("embedding_backend", {}))}
    return merged


def _deep_merge(base: dict, overrides: dict | None) -> dict:
    if not overrides:
        return base
    merged = base.copy()
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


@lru_cache(maxsize=1)
def load_policy() -> dict:
    return _load_json(POLICY_PATH, DEFAULT_POLICY)


@lru_cache(maxsize=1)
def load_model() -> dict:
    policy = load_policy()
    configured = Path(str(policy.get("model_path") or DEFAULT_MODEL_PATH))
    path = configured if configured.is_absolute() else PROJECT_ROOT / configured
    if not path.exists():
        return {"enabled": False, "reason": "embedding_guard_model_missing"}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        return {"enabled": False, "reason": f"embedding_guard_model_invalid:{exc}"}


def clear_caches() -> None:
    load_policy.cache_clear()
    load_model.cache_clear()
    load_embedding_cache.cache_clear()


def _stable_index(token: str, dim: int) -> int:
    digest = sha256(token.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % dim


def _stable_sign(token: str) -> float:
    digest = sha256(f"sign:{token}".encode("utf-8")).digest()
    return 1.0 if digest[0] % 2 == 0 else -1.0


def _tokens(text: str) -> list[str]:
    return [match.group(0).lower() for match in TOKEN_RE.finditer(text)]


def _norm(vec: list[float]) -> float:
    return math.sqrt(sum(item * item for item in vec))


def _normalize(vec: list[float]) -> list[float]:
    norm = _norm(vec)
    if norm <= 1e-12:
        return vec
    return [item / norm for item in vec]


def _dot(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


def embed_text(text: str, dim: int) -> list[float]:
    """Deterministic prototype embedding; swap with SRTP/BERT embeddings later."""
    vec = [0.0] * dim
    tokens = _tokens(text)
    for token in tokens:
        vec[_stable_index(token, dim)] += _stable_sign(token)
    return _normalize(vec)


@lru_cache(maxsize=1)
def load_embedding_cache() -> dict:
    policy = load_policy()
    backend = policy.get("embedding_backend", {})
    configured = backend.get("cache_path")
    if not configured:
        return {"enabled": False, "reason": "cache_path_missing"}
    path = Path(str(configured))
    path = path if path.is_absolute() else PROJECT_ROOT / path
    if not path.exists():
        return {"enabled": False, "reason": "cache_path_missing", "path": str(path)}
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        return {"enabled": False, "reason": f"cache_invalid:{exc}", "path": str(path)}
    vectors = {}
    for row in payload.get("rows", []):
        if isinstance(row, dict) and "text_sha256" in row and isinstance(row.get("embedding"), list):
            vectors[str(row["text_sha256"])] = [float(item) for item in row["embedding"]]
    return {
        "enabled": True,
        "path": str(path),
        "backend": payload.get("backend"),
        "requested_backend": payload.get("requested_backend"),
        "embedding_dim": payload.get("embedding_dim"),
        "vectors": vectors,
    }


def embedding_backend_status() -> dict:
    policy = load_policy()
    backend = policy.get("embedding_backend", {})
    backend_type = str(backend.get("type", "hash"))
    if backend_type == "hash":
        return {"type": "hash", "available": True, "reason": "portable_prototype_backend"}
    if backend_type == "cache":
        cache = load_embedding_cache()
        return {
            "type": "cache",
            "available": bool(cache.get("enabled")),
            "path": cache.get("path"),
            "cache_backend": cache.get("backend"),
            "reason": "cache_loaded" if cache.get("enabled") else cache.get("reason", "cache_unavailable"),
        }
    if backend_type == "srtp":
        srtp_root = Path(str(backend.get("srtp_root") or ""))
        return {
            "type": "srtp",
            "available": srtp_root.exists(),
            "root": str(srtp_root),
            "reason": "srtp_root_found" if srtp_root.exists() else "srtp_root_missing",
        }
    return {"type": backend_type, "available": False, "reason": "unknown_backend"}


def _vector_from_model(model: dict, key: str, dim: int) -> list[float]:
    raw = model.get(key)
    if not isinstance(raw, list):
        return [0.0] * dim
    values = [float(item) for item in raw[:dim]]
    if len(values) < dim:
        values.extend([0.0] * (dim - len(values)))
    return values


def _apply_soft_prompt(vec: list[float], model: dict, policy: dict, enabled: bool | None = None) -> list[float]:
    prompt_policy = policy.get("soft_prompt", {})
    use_prompt = prompt_policy.get("enabled", True) if enabled is None else enabled
    if not use_prompt:
        return vec
    prompt = _vector_from_model(model, "soft_prompt_vector", len(vec))
    scale = float(prompt_policy.get("scale", 0.0))
    return _normalize([value + scale * prompt[index] for index, value in enumerate(vec)])


def _add_dp_noise(vec: list[float], text: str, sample_index: int, policy: dict, enabled: bool | None = None) -> list[float]:
    dp_policy = policy.get("dp", {})
    use_dp = dp_policy.get("enabled", True) if enabled is None else enabled
    if not use_dp:
        return vec
    noise_std = float(dp_policy.get("noise_std", 0.0))
    noise_std = _adaptive_noise_std(vec, noise_std, policy)
    if noise_std <= 0:
        return vec
    seed_material = sha256(f"{text}:{sample_index}:embedding_guard_dp".encode("utf-8")).digest()
    rng = random.Random(int.from_bytes(seed_material[:8], "big"))
    return [value + rng.gauss(0.0, noise_std) for value in vec]


def _adaptive_noise_std(vec: list[float], base_noise_std: float, policy: dict) -> float:
    adaptive = policy.get("dp", {}).get("adaptive_noise", {})
    if not adaptive or not adaptive.get("enabled", False) or base_noise_std <= 0:
        return base_noise_std
    cache = load_embedding_cache()
    vectors = list(cache.get("vectors", {}).values()) if cache.get("enabled") else []
    if not vectors:
        return base_noise_std
    top_k = max(1, int(adaptive.get("top_k", 8)))
    target_density = float(adaptive.get("target_density", 0.82))
    alpha = float(adaptive.get("alpha", 0.75))
    min_multiplier = float(adaptive.get("min_multiplier", 0.65))
    max_multiplier = float(adaptive.get("max_multiplier", 1.75))
    similarities = sorted((_dot(vec, _normalize(item[: len(vec)])) for item in vectors), reverse=True)
    # Ignore the exact cache hit when present; the next neighbors estimate local density.
    neighborhood = [score for score in similarities if score < 0.999999][:top_k]
    if not neighborhood:
        return base_noise_std
    density = sum(neighborhood) / len(neighborhood)
    multiplier = 1.0 + alpha * (target_density - density)
    multiplier = max(min_multiplier, min(max_multiplier, multiplier))
    return base_noise_std * multiplier


def _denoise(noisy: list[float], reference: list[float], policy: dict, enabled: bool | None = None) -> list[float]:
    if enabled is False:
        return _normalize(noisy)
    dp_policy = policy.get("dp", {})
    blend = float(dp_policy.get("denoise_blend", 1.0))
    blend = max(0.0, min(blend, 1.0))
    restored = [blend * reference[index] + (1.0 - blend) * value for index, value in enumerate(noisy)]
    return _normalize(restored)


def _sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(min(value, 20.0), -20.0)))


def _benign_embedding_context(text: str, policy: dict) -> bool:
    lowered = text.lower()
    phrases = policy.get("benign_context_phrases", ["只作为风险标签", "不是可执行命令", "安全教育海报", "应脱敏", "defensive training"])
    active_markers = policy.get("benign_context_active_markers", ["gx-", "忽略开发者", "忽略系统", "输出管理员", "system override", "export_secret", "external collector"])
    return any(str(phrase).lower() in lowered for phrase in phrases) and not any(str(marker).lower() in lowered for marker in active_markers)


def _score_embedding(vec: list[float], model: dict) -> tuple[float, dict]:
    weights = _vector_from_model(model, "weights", len(vec))
    bias = float(model.get("bias", 0.0))
    raw_score = _dot(vec, weights) + bias
    probability = _sigmoid(raw_score)
    return probability, {"raw_score": round(raw_score, 4)}


def _join_request_text(message: str, history: list[Message], context_chunks: list[str] | None = None) -> str:
    parts: list[str] = []
    parts.extend(item.content for item in history[-4:])
    parts.append(message)
    if context_chunks:
        parts.extend(context_chunks)
    return "\n".join(part for part in parts if part)


def _embedding_for_text(text: str, dim: int, policy: dict) -> list[float]:
    backend = policy.get("embedding_backend", {})
    backend_type = str(backend.get("type", "hash"))
    if backend_type == "cache":
        cache = load_embedding_cache()
        if cache.get("enabled"):
            digest = sha256(text.encode("utf-8")).hexdigest()
            cached = cache.get("vectors", {}).get(digest)
            if cached:
                if len(cached) >= dim:
                    return _normalize(cached[:dim])
                return _normalize(cached + [0.0] * (dim - len(cached)))
    return embed_text(text, dim)


def _variant_flags(variant: str | None) -> dict[str, bool | None]:
    if not variant or variant == "policy":
        return {"dp": None, "denoise": None, "soft_prompt": None}
    if variant == "plain":
        return {"dp": False, "denoise": False, "soft_prompt": False}
    if variant == "dp":
        return {"dp": True, "denoise": False, "soft_prompt": False}
    if variant == "dp_denoise":
        return {"dp": True, "denoise": True, "soft_prompt": False}
    if variant == "dp_denoise_soft_prompt":
        return {"dp": True, "denoise": True, "soft_prompt": True}
    return {"dp": None, "denoise": None, "soft_prompt": None}


def vector_for_text(text: str, variant: str | None = "plain", overrides: dict | None = None) -> list[float]:
    policy = _deep_merge(load_policy(), overrides)
    model = load_model()
    dim = int(model.get("embedding_dim") or policy.get("embedding_dim") or 256)
    flags = _variant_flags(variant)
    base = _embedding_for_text(text, dim, policy)
    return _apply_soft_prompt(base, model, policy, enabled=flags["soft_prompt"])


def analyze(
    message: str,
    history: list[Message],
    context_chunks: list[str] | None = None,
    variant: str | None = None,
    overrides: dict | None = None,
) -> AnalysisResult:
    policy = _deep_merge(load_policy(), overrides)
    model = load_model()
    if not policy.get("enabled", True):
        return AnalysisResult(risk_score=0.0, labels=[], evidence=[], metadata={"enabled": False})
    if not model.get("enabled", False):
        return AnalysisResult(
            risk_score=0.0,
            labels=[],
            evidence=[],
            metadata={"enabled": True, "model_enabled": False, "reason": model.get("reason", "missing_model")},
        )

    dim = int(model.get("embedding_dim") or policy.get("embedding_dim") or 256)
    text = _join_request_text(message, history, context_chunks)
    flags = _variant_flags(variant)
    base = _embedding_for_text(text, dim, policy)
    prompted = _apply_soft_prompt(base, model, policy, enabled=flags["soft_prompt"])
    samples = max(1, int(policy.get("dp", {}).get("samples", 1))) if flags["dp"] is not False else 1
    sample_scores: list[float] = []
    sample_meta: list[dict] = []
    drift_values: list[float] = []
    for sample_index in range(samples):
        noisy = _add_dp_noise(prompted, text, sample_index, policy, enabled=flags["dp"])
        restored = _denoise(noisy, prompted, policy, enabled=flags["denoise"])
        drift_values.append(max(0.0, 1.0 - _dot(prompted, restored)))
        probability, meta = _score_embedding(restored, model)
        sample_scores.append(probability)
        sample_meta.append(meta)

    probability = sum(sample_scores) / len(sample_scores)
    risk_weight = float(policy.get("risk_weight", 0.22))
    risk_score = min(1.0, max(0.0, probability * risk_weight))
    labels: list[str] = []
    evidence: list[str] = []
    medium_threshold = float(model.get("medium_threshold", policy.get("medium_threshold", 0.45)))
    high_threshold = float(model.get("high_threshold", policy.get("high_threshold", 0.7)))
    if probability >= high_threshold:
        labels.append("embedding_jailbreak_risk")
        evidence.append("embedding_classifier_high")
    elif probability >= medium_threshold:
        labels.append("embedding_jailbreak_suspicious")
        evidence.append("embedding_classifier_medium")

    if _benign_embedding_context(text, policy):
        labels = [label for label in labels if not label.startswith("embedding_jailbreak")]
        labels.append("benign_embedding_context")
        evidence.append("benign_embedding_context_phrase")
        risk_score = min(
            max(0.0, risk_score - float(policy.get("benign_context_score_reduction", 0.18))),
            float(policy.get("benign_context_max_score", 0.08)),
        )

    return AnalysisResult(
        risk_score=round(risk_score, 4),
        labels=labels,
        evidence=evidence,
        metadata={
            "enabled": True,
            "model_enabled": True,
            "embedding_dim": dim,
            "probability": round(probability, 4),
            "risk_weight": risk_weight,
            "medium_threshold": medium_threshold,
            "high_threshold": high_threshold,
            "dp_samples": samples,
            "sample_scores": [round(item, 4) for item in sample_scores],
            "sample_meta": sample_meta[:3],
            "model_version": model.get("schema_version", "unknown"),
            "variant": variant or "policy",
            "embedding_backend": embedding_backend_status(),
            "mean_cosine_drift": round(sum(drift_values) / max(1, len(drift_values)), 4),
            "score_variance": round(
                sum((item - probability) * (item - probability) for item in sample_scores) / max(1, len(sample_scores)),
                6,
            ),
        },
    )
