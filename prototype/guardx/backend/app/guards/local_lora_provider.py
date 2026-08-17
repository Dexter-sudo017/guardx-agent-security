from __future__ import annotations

import hashlib
import json
import os
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.models import AnalysisResult


PROJECT_ROOT = Path(__file__).resolve().parents[5]
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "Qwen2.5-0.5B-Instruct"
DEFAULT_ADAPTER_DIR = PROJECT_ROOT / "models" / "guardx-local-lora-semantic-classifier-gpu-300"
JSON_RE = re.compile(r"\{.*?\}", re.S)


def _enabled() -> bool:
    return os.environ.get("GUARDX_LOCAL_LORA_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}


def _model_path() -> Path:
    return Path(os.environ.get("GUARDX_LOCAL_LORA_MODEL_PATH", str(DEFAULT_MODEL_PATH)))


def _adapter_dir() -> Path:
    return Path(os.environ.get("GUARDX_LOCAL_LORA_ADAPTER_DIR", str(DEFAULT_ADAPTER_DIR)))


def _max_score() -> float:
    return max(0.0, min(float(os.environ.get("GUARDX_LOCAL_LORA_MAX_SCORE", "0.16")), 0.35))


def _max_new_tokens() -> int:
    return max(8, min(int(os.environ.get("GUARDX_LOCAL_LORA_MAX_NEW_TOKENS", "80")), 160))


def _text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def _messages(text: str, surface: str) -> list[dict[str, str]]:
    return [
        {
            "role": "system",
            "content": "You are GuardX-Semantic, a defensive security classifier. Return compact JSON only.",
        },
        {
            "role": "user",
            "content": (
                "Classify whether this GuardX input is risky. Consider prompt injection, jailbreak, "
                "tool misuse, data exfiltration, OCR hidden instructions, and benign security education.\n\n"
                f"surface={surface}\n"
                f"text:\n{text[:2400]}"
            ),
        },
    ]


def _format_messages(tokenizer: Any, messages: list[dict[str, str]]) -> str:
    if hasattr(tokenizer, "apply_chat_template"):
        return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    return "\n".join(f"{item.get('role', 'user')}: {item.get('content', '')}" for item in messages) + "\nassistant:"


def _parse_prediction(text: str) -> dict[str, Any]:
    match = JSON_RE.search(text)
    parsed: dict[str, Any] = {}
    if match:
        try:
            parsed = json.loads(match.group(0))
        except Exception:
            parsed = {}
    lowered = text.lower()
    risky_value = parsed.get("risky")
    label = str(parsed.get("label", "")).lower()
    route = str(parsed.get("route", "")).lower()
    if isinstance(risky_value, bool):
        risky = risky_value
    elif label in {"risky", "unsafe", "attack", "malicious"} or route in {"review", "block", "review_or_block"}:
        risky = True
    elif label in {"benign", "safe", "allow"} or route == "allow":
        risky = False
    elif any(marker in lowered for marker in ('"risky": true', "'risky': true", "review_or_block", "label\": \"risky")):
        risky = True
    elif any(marker in lowered for marker in ('"risky": false', "'risky': false", "route\": \"allow", "label\": \"benign")):
        risky = False
    else:
        risky = False
    confidence_raw = parsed.get("confidence", parsed.get("score", 0.68 if risky else 0.0))
    try:
        confidence = max(0.0, min(float(confidence_raw), 1.0))
    except Exception:
        confidence = 0.68 if risky else 0.0
    return {
        "risky": risky,
        "confidence": confidence,
        "parse_ok": bool(parsed),
        "label": str(parsed.get("label", "risky" if risky else "benign")),
        "risk_type": str(parsed.get("risk_type", parsed.get("type", "local_lora_semantic_risk" if risky else "benign"))),
        "route": str(parsed.get("route", "review" if risky else "allow")),
        "output_hash": _text_hash(text),
    }


@lru_cache(maxsize=1)
def _load_runtime() -> dict[str, Any]:
    started = time.perf_counter()
    model_path = _model_path()
    adapter_dir = _adapter_dir()
    try:
        import torch
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer

        device = "cuda" if torch.cuda.is_available() and os.environ.get("GUARDX_LOCAL_LORA_DEVICE", "auto") != "cpu" else "cpu"
        dtype = torch.float32 if device == "cpu" else torch.float16
        tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True, trust_remote_code=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        base = AutoModelForCausalLM.from_pretrained(
            model_path,
            local_files_only=True,
            trust_remote_code=True,
            torch_dtype=dtype,
            device_map=None if device == "cpu" else "auto",
        )
        if device == "cpu":
            base.to("cpu")
        model = PeftModel.from_pretrained(base, adapter_dir, local_files_only=True)
        model.eval()
        return {
            "ok": True,
            "tokenizer": tokenizer,
            "model": model,
            "device": device,
            "model_path": str(model_path),
            "adapter_dir": str(adapter_dir),
            "load_latency_ms": round((time.perf_counter() - started) * 1000.0, 3),
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": repr(exc)[:240],
            "model_path": str(model_path),
            "adapter_dir": str(adapter_dir),
            "load_latency_ms": round((time.perf_counter() - started) * 1000.0, 3),
        }


def analyze_text(text: str, surface: str = "input") -> AnalysisResult:
    if not _enabled():
        return AnalysisResult(risk_score=0.0, labels=[], evidence=[], metadata={"enabled": False, "provider_id": "local_lora_semantic_provider"})

    runtime = _load_runtime()
    base_metadata = {
        "enabled": True,
        "provider_id": "local_lora_semantic_provider",
        "model_path": Path(str(runtime.get("model_path", ""))).name,
        "adapter_dir": Path(str(runtime.get("adapter_dir", ""))).name,
        "load_latency_ms": runtime.get("load_latency_ms"),
        "surface": surface,
        "input_hash": _text_hash(text),
    }
    if not runtime.get("ok"):
        return AnalysisResult(
            risk_score=0.0,
            labels=["local_lora_provider_unavailable"],
            evidence=[],
            metadata=base_metadata | {"ok": False, "error": runtime.get("error")},
        )

    started = time.perf_counter()
    try:
        tokenizer = runtime["tokenizer"]
        model = runtime["model"]
        prompt = _format_messages(tokenizer, _messages(text, surface))
        inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=768)
        inputs = {key: value.to(model.device) for key, value in inputs.items()}
        with __import__("torch").no_grad():
            output_ids = model.generate(
                **inputs,
                max_new_tokens=_max_new_tokens(),
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id,
            )
        generated = tokenizer.decode(output_ids[0][inputs["input_ids"].shape[-1] :], skip_special_tokens=True)
        parsed = _parse_prediction(generated)
    except Exception as exc:
        return AnalysisResult(
            risk_score=0.0,
            labels=["local_lora_inference_error"],
            evidence=[],
            metadata=base_metadata | {"ok": False, "error": repr(exc)[:240]},
        )

    latency_ms = round((time.perf_counter() - started) * 1000.0, 3)
    if not parsed["parse_ok"]:
        return AnalysisResult(
            risk_score=0.0,
            labels=["local_lora_parse_fallback"],
            evidence=[f"output_hash={parsed['output_hash']}"],
            metadata=base_metadata | {"ok": True, "parse_ok": False, "latency_ms": latency_ms, "device": runtime.get("device")},
        )
    if not parsed["risky"]:
        return AnalysisResult(
            risk_score=0.0,
            labels=["local_lora_benign"],
            evidence=[f"output_hash={parsed['output_hash']}", f"route={parsed['route']}"],
            metadata=base_metadata
            | {
                "ok": True,
                "parse_ok": True,
                "latency_ms": latency_ms,
                "device": runtime.get("device"),
                "confidence": parsed["confidence"],
                "label": parsed["label"],
                "risk_type": parsed["risk_type"],
                "route": parsed["route"],
            },
        )
    score = round(min(_max_score(), max(0.04, parsed["confidence"] * _max_score())), 4)
    return AnalysisResult(
        risk_score=score,
        labels=sorted({"local_lora_semantic_risk", f"local_lora_{parsed['risk_type']}"}),
        evidence=[f"output_hash={parsed['output_hash']}", f"route={parsed['route']}"],
        metadata=base_metadata
        | {
            "ok": True,
            "parse_ok": True,
            "latency_ms": latency_ms,
            "device": runtime.get("device"),
            "confidence": parsed["confidence"],
            "label": parsed["label"],
            "risk_type": parsed["risk_type"],
            "route": parsed["route"],
        },
    )
