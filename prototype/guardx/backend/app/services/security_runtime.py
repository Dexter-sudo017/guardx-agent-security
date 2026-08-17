import json
import os
from typing import Any

from fastapi import Request

from app.services.admin_runtime import PROJECT_ROOT, web_access_allowed, web_token


DEPLOYMENT_SECURITY_CONFIG = PROJECT_ROOT / "configs" / "guardx_deployment_security_policy.json"


def deployment_security_policy() -> dict[str, Any]:
    fallback = {
        "rate_limit": {
            "enabled": False,
            "default_requests_per_minute": 120,
            "action_guard_requests_per_minute": 240,
        }
    }
    if not DEPLOYMENT_SECURITY_CONFIG.exists():
        return fallback
    try:
        loaded = json.loads(DEPLOYMENT_SECURITY_CONFIG.read_text(encoding="utf-8"))
    except Exception:
        return fallback
    merged = fallback.copy()
    merged.update(loaded)
    merged["rate_limit"] = {**fallback["rate_limit"], **dict(loaded.get("rate_limit", {}))}
    return merged


def rate_limit_key(raw_request: Request) -> str:
    token = raw_request.headers.get("x-guardx-token") or raw_request.headers.get("authorization") or raw_request.cookies.get("guardx_web_token", "")
    client = raw_request.client.host if raw_request.client else "unknown"
    return f"{client}:{token[-12:] if token else 'anon'}:{raw_request.url.path}"


def rate_limit_per_minute(path: str) -> int:
    policy = deployment_security_policy().get("rate_limit", {})
    default = int(os.environ.get("GUARDX_RATE_LIMIT_PER_MINUTE", policy.get("default_requests_per_minute", 120)))
    if path.startswith("/v1/action_guard"):
        return int(os.environ.get("GUARDX_ACTION_RATE_LIMIT_PER_MINUTE", policy.get("action_guard_requests_per_minute", 240)))
    return default


def rate_limit_enabled() -> bool:
    policy = deployment_security_policy().get("rate_limit", {})
    return os.environ.get("GUARDX_RATE_LIMIT_ENABLED", str(policy.get("enabled", False))).lower() in {"1", "true", "yes", "on"}


__all__ = [
    "DEPLOYMENT_SECURITY_CONFIG",
    "deployment_security_policy",
    "rate_limit_enabled",
    "rate_limit_key",
    "rate_limit_per_minute",
    "web_access_allowed",
    "web_token",
]
