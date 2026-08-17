from typing import Any

from fastapi import APIRouter

from app.services.model_output_health import run_model_output_health

router = APIRouter()


@router.post("/v1/audit/run_model_output_health")
def run_model_output_health_probe(
    models: str = "mock-safe-model",
    run_id: str | None = None,
    timeout_s: float = 45.0,
) -> dict[str, Any]:
    return run_model_output_health(
        models=models.split(","),
        run_id=run_id,
        timeout_s=timeout_s,
    )
