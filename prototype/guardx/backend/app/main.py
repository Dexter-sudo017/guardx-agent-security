from fastapi import FastAPI

from app.middleware.security import configure_middlewares
from app.routes import action_guard, admin, baseline, demo_assets, executor_integration, guarded, portal_final, proxy, runtime_actions
from app.services.admin_runtime import set_app


def create_app() -> FastAPI:
    app = FastAPI(title="GuardX Prototype", version="0.1.0")
    set_app(app)
    configure_middlewares(app)
    app.include_router(admin.router)
    app.include_router(guarded.router)
    app.include_router(demo_assets.router)
    app.include_router(baseline.router)
    app.include_router(proxy.router)
    app.include_router(action_guard.router)
    app.include_router(runtime_actions.router)
    app.include_router(executor_integration.router)
    app.include_router(portal_final.router)
    portal_final.configure_nf_portal(app)
    return app


app = create_app()
