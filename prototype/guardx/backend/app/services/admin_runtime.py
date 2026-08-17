import os
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse


APP_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = APP_ROOT.parents[3]
STATIC_INDEX = APP_ROOT / "static" / "index.html"
STATIC_DASHBOARD = APP_ROOT / "static" / "dashboard.html"
STATIC_GATEWAY = APP_ROOT / "static" / "gateway.html"
STATIC_LOGIN = APP_ROOT / "static" / "login.html"
STATIC_PORTAL = APP_ROOT / "static" / "portal.html"
STATIC_EXPERIMENT_DASHBOARD = PROJECT_ROOT / "evaluation" / "dashboard" / "index.html"
STATIC_MATRIX_DASHBOARD = PROJECT_ROOT / "prototype" / "guardx" / "backend" / "data" / "experiment_runs" / "latest_matrix_dashboard.html"

_app_ref = None


def web_token() -> str:
    return os.environ.get("GUARDX_WEB_TOKEN", "").strip()


def _unauthenticated_local_access_allowed(raw_request: Request) -> bool:
    enabled = os.environ.get("GUARDX_WEB_ALLOW_UNAUTHENTICATED_LOCALHOST", "1").strip().lower() in {"1", "true", "yes", "on"}
    host = str(raw_request.client.host if raw_request.client else "").lower()
    return enabled and host in {"127.0.0.1", "::1", "localhost", "testclient"}


def _unauthenticated_public_demo_allowed() -> bool:
    return os.environ.get("GUARDX_WEB_ALLOW_UNAUTHENTICATED_PUBLIC_DEMO", "0").strip().lower() in {"1", "true", "yes", "on"}


def web_access_allowed(raw_request: Request) -> bool:
    expected = web_token()
    if not expected:
        # Remote anonymous access is opt-in and used only by the short-lived
        # competition tunnel script. Every other deployment remains fail-closed.
        return _unauthenticated_local_access_allowed(raw_request) or _unauthenticated_public_demo_allowed()
    supplied = raw_request.cookies.get("guardx_web_token", "")
    if not supplied:
        supplied = raw_request.headers.get("x-guardx-web-token", "")
    if not supplied:
        supplied = raw_request.headers.get("x-guardx-token", "")
    bearer = raw_request.headers.get("authorization", "")
    if bearer.lower().startswith("bearer "):
        supplied = bearer.split(" ", 1)[1].strip()
    return supplied == expected


def protected_html(raw_request: Request, static_path: Path) -> Any:
    if not web_access_allowed(raw_request):
        return RedirectResponse(f"/login?next={raw_request.url.path}", status_code=302)
    return HTMLResponse(static_path.read_text(encoding="utf-8"))


def set_app(app) -> None:
    global _app_ref
    _app_ref = app


def get_app():
    if _app_ref is None:
        raise RuntimeError("GuardX FastAPI app reference has not been initialized.")
    return _app_ref


__all__ = [
    "PROJECT_ROOT",
    "STATIC_DASHBOARD",
    "STATIC_EXPERIMENT_DASHBOARD",
    "STATIC_GATEWAY",
    "STATIC_INDEX",
    "STATIC_LOGIN",
    "STATIC_MATRIX_DASHBOARD",
    "STATIC_PORTAL",
    "get_app",
    "protected_html",
    "set_app",
    "web_access_allowed",
    "web_token",
]
