from __future__ import annotations

from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.contracts.executor_integration import ApprovalDecisionRequest
from app.integration.api_binding import configure_executor_integration
from app.integration.portal_runtime import PROJECT_ROOT, PortalRuntimeManager, PortalRuntimeService


router = APIRouter(tags=["national-final-portal"])


def _final_asset_root():
    candidates = (
        PROJECT_ROOT / "reviewer_console",
        PROJECT_ROOT.parents[1] / "05_demo_assets" / "reviewer_console_v2",
    )
    return next((path for path in candidates if path.is_dir()), candidates[0])


FINAL_ASSET_ROOT = _final_asset_root()


def _service(request: Request) -> PortalRuntimeService:
    manager = getattr(request.app.state, "nf_portal_manager", None)
    if not isinstance(manager, PortalRuntimeManager):
        raise HTTPException(status_code=503, detail="NF Portal runtime is not configured")
    service = manager.service
    configure_executor_integration(request.app, service.executor_service)
    return service


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail=str(exc).strip("'"))
    return HTTPException(status_code=409, detail=str(exc))


@router.get("/portal-final", include_in_schema=False)
def portal_final_redirect() -> RedirectResponse:
    return RedirectResponse("/final/", status_code=302)


@router.get("/v1/reviewer/status")
def reviewer_status(request: Request) -> dict[str, Any]:
    return _service(request).status()


@router.post("/v1/reviewer/scenarios/{scenario_id}/run")
def reviewer_scenario_run(scenario_id: str, body: dict[str, Any], request: Request) -> dict[str, Any]:
    variant = str(body.get("variant") or "clean").lower()
    mapping = {
        ("rag", "clean"): "D01",
        ("rag", "attack"): "D03",
        ("vlm", "clean"): "D01",
        ("vlm", "attack"): "D05",
        ("agent", "clean"): "D01",
        ("agent", "attack"): "D06",
    }
    case_id = mapping.get((scenario_id.lower(), variant))
    if case_id is None:
        raise HTTPException(status_code=404, detail="reviewer live scenario is not configured")
    try:
        result = _service(request).run_case(case_id)
    except (KeyError, PermissionError, ValueError) as exc:
        raise _http_error(exc) from exc
    route = "ALLOW" if result["action_outcome"] == "ALLOW" else "BLOCK"
    timeline = result["event_timeline"]
    return {
        "risk": result["policy_decision"].get("risk_score", 0.0),
        "route": route,
        "provider": result["provider_mode"],
        "executor_state": result["executor_result"]["execution_state"],
        "trace_id": result["run_id"],
        "evidence_id": result["evidence_replay_verify"]["record_hash"],
        "stages": [
            {
                "offset_ms": index * 80,
                "stage": event["stage"],
                "detail": event["detail"],
                "status": event["status"],
            }
            for index, event in enumerate(timeline)
        ],
        "ledger": {
            "execution_permit": result["capability_verification"].get("granted", False),
            "runner_invoked": result["executor_result"]["executed"],
            "side_effect": result["side_effect_proof"]["reported_side_effect_count"] > 0,
            "final_action": result["action_outcome"],
            "evidence_id": result["run_id"],
        },
    }


@router.get("/v1/portal/status")
def portal_status(request: Request) -> dict[str, Any]:
    return _service(request).status()


@router.get("/v1/portal/demo-cases")
def portal_demo_cases(request: Request) -> dict[str, Any]:
    service = _service(request)
    return {"runtime": service.status(), "cases": service.list_cases()}


@router.post("/v1/portal/demo-cases/{case_id}/run")
def portal_run_case(case_id: str, request: Request) -> dict[str, Any]:
    try:
        return _service(request).run_case(case_id)
    except (KeyError, PermissionError, ValueError) as exc:
        raise _http_error(exc) from exc


@router.post("/v1/portal/contextual/evaluate")
def portal_contextual_evaluate(body: dict[str, Any], request: Request) -> dict[str, Any]:
    try:
        return _service(request).evaluate_context(body)
    except (KeyError, PermissionError, ValueError) as exc:
        raise _http_error(exc) from exc


@router.post("/v1/portal/approvals/{approval_id}/approve-and-resume")
def portal_approve_and_resume(
    approval_id: str,
    body: ApprovalDecisionRequest,
    request: Request,
) -> dict[str, Any]:
    try:
        return _service(request).approve_and_resume(approval_id, reason=body.reason)
    except (KeyError, PermissionError, ValueError) as exc:
        raise _http_error(exc) from exc


@router.get("/v1/portal/runs")
def portal_runs(request: Request) -> dict[str, Any]:
    service = _service(request)
    return {"mode": "READ_ONLY", "runs": service.evidence.list_runs()}


@router.get("/v1/portal/runs/{run_id}/replay")
def portal_replay(run_id: str, request: Request) -> dict[str, Any]:
    try:
        return _service(request).replay(run_id)
    except KeyError as exc:
        raise _http_error(exc) from exc


@router.get("/v1/portal/runs/{run_id}/verify")
def portal_verify(run_id: str, request: Request) -> dict[str, Any]:
    try:
        return _service(request).verify(run_id)
    except KeyError as exc:
        raise _http_error(exc) from exc


@router.get("/v1/portal/backend-state")
def portal_backend_state(request: Request) -> dict[str, Any]:
    return _service(request).backend_state()


def configure_nf_portal(app: FastAPI, manager: PortalRuntimeManager | None = None) -> PortalRuntimeManager:
    active_manager = manager or PortalRuntimeManager()
    app.state.nf_portal_manager = active_manager

    def startup() -> None:
        service = active_manager.initialize()
        configure_executor_integration(app, service.executor_service)

    app.router.add_event_handler("startup", startup)
    app.router.add_event_handler("shutdown", active_manager.close)
    app.mount("/final", StaticFiles(directory=FINAL_ASSET_ROOT, html=True), name="nf-final-portal")
    return active_manager
