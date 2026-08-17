from fastapi import APIRouter

from app.routes import admin_artifacts, admin_audit, admin_audit_maintenance, admin_audit_replay, admin_control, admin_decoder_probe, admin_eval, admin_experiment, admin_model_health, admin_pages, admin_security_insights

router = APIRouter()
router.include_router(admin_pages.router)
router.include_router(admin_control.router)
router.include_router(admin_decoder_probe.router)
router.include_router(admin_eval.router)
router.include_router(admin_audit.router)
router.include_router(admin_audit_replay.router)
router.include_router(admin_experiment.router)
router.include_router(admin_artifacts.router)
router.include_router(admin_model_health.router)
router.include_router(admin_audit_maintenance.router)
router.include_router(admin_security_insights.router)
