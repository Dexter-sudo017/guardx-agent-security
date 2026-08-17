from time import time

from fastapi import Request
from fastapi import FastAPI
from fastapi.responses import JSONResponse, RedirectResponse

from app.middleware.state import rate_limit_state
from app.services.security_runtime import rate_limit_enabled, rate_limit_key, rate_limit_per_minute, web_access_allowed, web_token


async def guardx_rate_limit(raw_request: Request, call_next):
    if not rate_limit_enabled() or raw_request.url.path in {"/healthz", "/favicon.ico"}:
        return await call_next(raw_request)
    now = time()
    window_start = now - 60.0
    key = rate_limit_key(raw_request)
    recent = [item for item in rate_limit_state[key] if item >= window_start]
    limit = rate_limit_per_minute(raw_request.url.path)
    if len(recent) >= limit:
        return JSONResponse(
            {
                "detail": "GuardX rate limit exceeded.",
                "limit_per_minute": limit,
                "retry_after_seconds": max(1, int(60 - (now - min(recent)))),
            },
            status_code=429,
            headers={"Retry-After": "60"},
        )
    recent.append(now)
    rate_limit_state[key] = recent
    response = await call_next(raw_request)
    response.headers["X-GuardX-RateLimit-Limit"] = str(limit)
    response.headers["X-GuardX-RateLimit-Remaining"] = str(max(0, limit - len(recent)))
    return response


async def require_web_access(raw_request: Request, call_next):
    public_paths = {"/healthz", "/login", "/v1/web_login", "/favicon.ico"}
    if raw_request.url.path in public_paths:
        return await call_next(raw_request)
    if web_access_allowed(raw_request):
        return await call_next(raw_request)
    if raw_request.url.path.startswith("/v1/"):
        return JSONResponse({"detail": "GuardX access token missing or invalid."}, status_code=401)
    return RedirectResponse(f"/login?next={raw_request.url.path}", status_code=302)





def configure_middlewares(app: FastAPI) -> None:
    app.middleware("http")(guardx_rate_limit)
    app.middleware("http")(require_web_access)
