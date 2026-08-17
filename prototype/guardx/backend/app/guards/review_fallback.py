from __future__ import annotations

import json
import os
import re
from time import perf_counter
from typing import Any
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError


PROVIDER_DEFAULTS = {
    "kimi": {
        "base_url": "https://api.moonshot.ai/v1/chat/completions",
        "model": "kimi-k2-0711-preview",
    },
    "moonshot": {
        "base_url": "https://api.moonshot.ai/v1/chat/completions",
        "model": "kimi-k2-0711-preview",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/chat/completions",
        "model": "deepseek-chat",
    },
    "dashscope": {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        "model": "qwen-plus",
    },
    "qwen": {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        "model": "qwen-plus",
    },
    "bailian": {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        "model": "qwen-plus",
    },
    "zhipu": {
        "base_url": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        "model": "glm-4-flash",
    },
}


SYSTEM_PROMPT = """You are a strict safety classifier for an LLM gateway.
Return only compact JSON with keys: decision, risk, reason.
decision must be one of: allow, block, review.
Classify the user text, not the policy description. Prefer review when benign and harmful readings are both plausible."""


def _env_bool(name: str, fallback: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return fallback
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _provider_config() -> dict[str, str]:
    provider = os.environ.get("GUARDX_REVIEW_LLM_PROVIDER", "deepseek").strip().lower()
    defaults = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["deepseek"])
    return {
        "provider": provider,
        "base_url": os.environ.get("GUARDX_REVIEW_LLM_BASE_URL", defaults["base_url"]).strip(),
        "model": os.environ.get("GUARDX_REVIEW_LLM_MODEL", defaults["model"]).strip(),
        "api_key_env": os.environ.get("GUARDX_REVIEW_LLM_API_KEY_ENV", "GUARDX_REVIEW_LLM_API_KEY").strip(),
    }


def _extract_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?", "", stripped, flags=re.IGNORECASE).strip()
        stripped = re.sub(r"```$", "", stripped).strip()
    try:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", stripped, flags=re.DOTALL)
        if not match:
            return {}
        try:
            parsed = json.loads(match.group(0))
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}


def _normalize_decision(value: Any) -> str:
    decision = str(value or "review").strip().lower()
    if decision in {"allow", "safe"}:
        return "allow"
    if decision in {"block", "deny", "unsafe"}:
        return "block"
    return "review"


def review(text: str, routing_metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    if not _env_bool("GUARDX_REVIEW_LLM_ENABLED", False):
        return {"enabled": False, "decision": "review", "reason": "disabled"}
    config = _provider_config()
    api_key = os.environ.get(config["api_key_env"], "").strip()
    if not api_key:
        return {"enabled": True, "decision": "review", "reason": "missing_api_key", "provider": config["provider"]}
    started = perf_counter()
    prompt = {
        "routing_metadata": routing_metadata or {},
        "text": text[:4000],
    }
    body = {
        "model": config["model"],
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
        ],
        "temperature": 0,
        "max_tokens": 160,
        "response_format": {"type": "json_object"},
    }
    request = urllib_request.Request(
        config["base_url"],
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib_request.urlopen(request, timeout=float(os.environ.get("GUARDX_REVIEW_LLM_TIMEOUT", "20"))) as response:
            raw = response.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw)
    except HTTPError as exc:
        return {"enabled": True, "decision": "review", "reason": f"http_error_{exc.code}", "provider": config["provider"], "latency_ms": round((perf_counter() - started) * 1000.0, 3)}
    except (URLError, TimeoutError, json.JSONDecodeError, Exception) as exc:
        return {"enabled": True, "decision": "review", "reason": f"{type(exc).__name__}", "provider": config["provider"], "latency_ms": round((perf_counter() - started) * 1000.0, 3)}
    content = ""
    try:
        content = str(parsed["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError):
        content = ""
    judged = _extract_json(content)
    risk = judged.get("risk", 0.5)
    try:
        risk_value = max(0.0, min(1.0, float(risk)))
    except (TypeError, ValueError):
        risk_value = 0.5
    return {
        "enabled": True,
        "provider": config["provider"],
        "model": config["model"],
        "decision": _normalize_decision(judged.get("decision")),
        "risk": round(risk_value, 6),
        "reason": str(judged.get("reason", ""))[:240],
        "latency_ms": round((perf_counter() - started) * 1000.0, 3),
    }
