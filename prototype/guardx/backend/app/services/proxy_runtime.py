import json
import os
from pathlib import Path
from time import perf_counter
from typing import Any
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

from fastapi import HTTPException, Request


APP_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = APP_ROOT.parents[3]
ANYTHINGLLM_WORKSPACE_CONFIG = PROJECT_ROOT / "configs" / "anythingllm_proxy_workspaces.json"
ANYTHINGLLM_WORKSPACE_EXAMPLE_CONFIG = PROJECT_ROOT / "configs" / "anythingllm_proxy_workspaces.example.json"


def blocking_action(action: str) -> bool:
    return action in {"rewrite", "block", "terminate", "redact_output"}


def anythingllm_context_for_workspace(workspace_slug: str) -> list[str]:
    workspace = anythingllm_workspace_config(workspace_slug)
    configured = os.environ.get("GUARDX_PROXY_CONTEXT_FILE") or workspace.get("context_file")
    candidates = []
    if configured:
        candidates.append(Path(configured))
    candidates.append(PROJECT_ROOT / "external_targets" / "anythingllm" / "rag_injection_override_sample.txt")
    for candidate in candidates:
        path = candidate if candidate.is_absolute() else PROJECT_ROOT / candidate
        if path.exists():
            return [path.read_text(encoding="utf-8")]
    return []


def anythingllm_workspace_config(workspace_slug: str) -> dict[str, Any]:
    config_path = ANYTHINGLLM_WORKSPACE_CONFIG if ANYTHINGLLM_WORKSPACE_CONFIG.exists() else ANYTHINGLLM_WORKSPACE_EXAMPLE_CONFIG
    if not config_path.exists():
        return {}
    try:
        loaded = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    default = loaded.get("default") if isinstance(loaded.get("default"), dict) else {}
    workspaces = loaded.get("workspaces") if isinstance(loaded.get("workspaces"), dict) else {}
    workspace = workspaces.get(workspace_slug) if isinstance(workspaces.get(workspace_slug), dict) else {}
    merged = default.copy()
    merged.update(workspace)
    return merged


def forward_anythingllm(base_url: str, workspace_slug: str, api_key: str, payload: dict[str, Any], timeout: int = 240) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}/api/v1/workspace/{workspace_slug}/chat"
    body = json.dumps(payload).encode("utf-8")
    req = urllib_request.Request(
        url,
        data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    started = perf_counter()
    try:
        with urllib_request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return {"status": "completed", "http_status": response.status, "body": json.loads(raw), "latency_ms": round((perf_counter() - started) * 1000.0, 3)}
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        return {"status": "http_error", "http_status": exc.code, "body": {"raw_text": raw}, "latency_ms": round((perf_counter() - started) * 1000.0, 3)}
    except URLError as exc:
        return {"status": "error", "error": str(exc.reason), "latency_ms": round((perf_counter() - started) * 1000.0, 3)}
    except Exception as exc:
        return {"status": "error", "error": str(exc), "latency_ms": round((perf_counter() - started) * 1000.0, 3)}


def forward_json_target(url: str, headers: dict[str, str], payload: dict[str, Any], timeout: int = 240) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    merged_headers = {"Content-Type": "application/json"}
    merged_headers.update(headers)
    req = urllib_request.Request(url, data=body, headers=merged_headers, method="POST")
    started = perf_counter()
    try:
        with urllib_request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            parsed: Any
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {"raw_text": raw}
            return {"status": "completed", "http_status": response.status, "body": parsed, "latency_ms": round((perf_counter() - started) * 1000.0, 3)}
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        return {"status": "http_error", "http_status": exc.code, "body": {"raw_text": raw}, "latency_ms": round((perf_counter() - started) * 1000.0, 3)}
    except URLError as exc:
        return {"status": "error", "error": str(exc.reason), "latency_ms": round((perf_counter() - started) * 1000.0, 3)}
    except Exception as exc:
        return {"status": "error", "error": str(exc), "latency_ms": round((perf_counter() - started) * 1000.0, 3)}


def extract_path_value(body: Any, path: str) -> Any:
    current = body
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            current = current[index] if index < len(current) else None
        else:
            return None
    return current


def extract_answer_text(body: Any, candidates: list[str]) -> str:
    if isinstance(body, str):
        return body
    if not isinstance(body, dict):
        return ""
    for field in candidates:
        value = extract_path_value(body, field)
        if isinstance(value, str):
            return value
    for field in ("textResponse", "answer", "response", "text", "message", "content", "output"):
        value = body.get(field)
        if isinstance(value, str):
            return value
    return ""


def require_proxy_token(raw_request: Request) -> None:
    expected = os.environ.get("GUARDX_PROXY_TOKEN", "").strip()
    if not expected:
        return
    bearer = raw_request.headers.get("authorization", "")
    header_token = raw_request.headers.get("x-guardx-token", "")
    supplied = header_token or raw_request.cookies.get("guardx_web_token", "")
    if bearer.lower().startswith("bearer "):
        supplied = bearer.split(" ", 1)[1].strip()
    if supplied != expected:
        raise HTTPException(status_code=401, detail="GuardX proxy token missing or invalid.")


__all__ = [
    "ANYTHINGLLM_WORKSPACE_CONFIG",
    "ANYTHINGLLM_WORKSPACE_EXAMPLE_CONFIG",
    "anythingllm_context_for_workspace",
    "anythingllm_workspace_config",
    "blocking_action",
    "extract_answer_text",
    "forward_anythingllm",
    "forward_json_target",
    "require_proxy_token",
]
