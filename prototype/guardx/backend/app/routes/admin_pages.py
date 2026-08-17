import os
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from app.demo_presets import list_presets
from app.services.admin_runtime import (
    STATIC_DASHBOARD,
    STATIC_EXPERIMENT_DASHBOARD,
    STATIC_GATEWAY,
    STATIC_INDEX,
    STATIC_LOGIN,
    STATIC_MATRIX_DASHBOARD,
    STATIC_PORTAL,
    protected_html,
    web_access_allowed,
    web_token,
)
from app.services.runtime_state import adapter_registry

router = APIRouter()


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/")
def console(raw_request: Request) -> Any:
    return protected_html(raw_request, STATIC_INDEX)


@router.get("/dashboard")
def dashboard(raw_request: Request) -> Any:
    return protected_html(raw_request, STATIC_DASHBOARD)


@router.get("/experiment-dashboard")
def experiment_dashboard(raw_request: Request) -> Any:
    if not web_access_allowed(raw_request):
        return RedirectResponse(f"/login?next={raw_request.url.path}", status_code=302)
    if not STATIC_EXPERIMENT_DASHBOARD.exists():
        raise HTTPException(status_code=404, detail="Experiment dashboard has not been generated yet.")
    return HTMLResponse(STATIC_EXPERIMENT_DASHBOARD.read_text(encoding="utf-8"))


@router.get("/matrix-dashboard")
def matrix_dashboard(raw_request: Request) -> Any:
    if not web_access_allowed(raw_request):
        return RedirectResponse(f"/login?next={raw_request.url.path}", status_code=302)
    if not STATIC_MATRIX_DASHBOARD.exists():
        raise HTTPException(status_code=404, detail="GuardX matrix dashboard has not been generated yet.")
    return HTMLResponse(STATIC_MATRIX_DASHBOARD.read_text(encoding="utf-8"))


@router.get("/gateway")
def gateway(raw_request: Request) -> Any:
    return protected_html(raw_request, STATIC_GATEWAY)


@router.get("/login")
def login() -> HTMLResponse:
    return HTMLResponse(STATIC_LOGIN.read_text(encoding="utf-8"))


@router.get("/portal")
def portal(raw_request: Request) -> Any:
    return protected_html(raw_request, STATIC_PORTAL)


@router.post("/v1/web_login")
async def web_login(raw_request: Request) -> JSONResponse:
    expected = web_token()
    payload = await raw_request.json()
    supplied = str(payload.get("token") or "").strip()
    if expected and supplied != expected:
        raise HTTPException(status_code=401, detail="Invalid GuardX web token.")
    response = JSONResponse({"ok": True, "auth_enabled": bool(expected)})
    if expected:
        response.set_cookie("guardx_web_token", supplied, httponly=True, samesite="lax")
    return response


@router.post("/v1/web_logout")
def web_logout() -> JSONResponse:
    response = JSONResponse({"ok": True})
    response.delete_cookie("guardx_web_token")
    return response


@router.get("/v1/models")
def list_models() -> list[dict[str, Any]]:
    return [item.model_dump() for item in adapter_registry.list_models()]


def _provider_identity(model_name: str, adapter_type: str) -> tuple[str, str, str]:
    if adapter_type in {"ollama", "ollama_vlm"}:
        return "ollama", "本地 Ollama", "local"
    if model_name.startswith("deepseek-"):
        return "deepseek", "DeepSeek API", "api"
    if model_name.startswith("dashscope-"):
        return "dashscope", "阿里百炼 / 通义千问", "api"
    if model_name.startswith("kimi-"):
        return "kimi", "Kimi / Moonshot", "api"
    if model_name.startswith("zhipu-"):
        return "zhipu", "智谱 GLM", "api"
    if model_name.startswith("fourrouter-"):
        return "fourrouter", "4Router · GPT / Claude", "api"
    return "enterprise", "OpenAI-compatible Gateway", "api"


@router.get("/v1/providers/status")
def provider_status() -> dict[str, Any]:
    grouped: dict[str, dict[str, Any]] = {}
    for model in adapter_registry.list_models():
        if model.adapter_type == "mock":
            continue
        spec = adapter_registry.get_spec(model.name)
        provider_id, label, mode = _provider_identity(model.name, model.adapter_type)
        base_url = str(spec.get("base_url") or "")
        base_url_env = str(spec.get("base_url_env") or "")
        if base_url_env and os.environ.get(base_url_env):
            base_url = os.environ[base_url_env]
        api_key_env = str(spec.get("api_key_env") or "")
        entry = grouped.setdefault(
            provider_id,
            {
                "id": provider_id,
                "label": label,
                "mode": mode,
                "configured": False,
                "status": "OFFLINE" if mode == "local" else "NEEDS SERVER KEY",
                "endpoint_host": urlparse(base_url).netloc or ("127.0.0.1:11434" if mode == "local" else "server-managed"),
                "credential_env": api_key_env or None,
                "credential_policy": "server-environment-only",
                "models": [],
            },
        )
        entry["models"].append(
            {
                "name": model.name,
                "description": model.description,
                "configured": model.configured,
                "upstream_model": spec.get("upstream_model"),
                "capabilities": model.capabilities,
            }
        )
        entry["configured"] = bool(entry["configured"] or model.configured)
    providers = list(grouped.values())
    for provider in providers:
        if provider["configured"]:
            provider["status"] = "READY"
    providers.sort(key=lambda item: (0 if item["mode"] == "local" else 1, item["label"]))
    return {
        "credential_policy": "server-environment-only",
        "credentials_exposed": False,
        "providers": providers,
    }


@router.get("/v1/demo/presets")
def demo_presets() -> list[dict[str, Any]]:
    return list_presets()
