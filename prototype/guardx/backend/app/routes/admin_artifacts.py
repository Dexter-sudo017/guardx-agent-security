from typing import Any

from fastapi import APIRouter

from app.services.experiment_artifact_health import build_experiment_artifact_health


router = APIRouter()


@router.get("/v1/audit/experiment_artifact_health")
def get_experiment_artifact_health(
    profile: str | None = None,
    kinds: str | None = None,
    max_age_seconds: int | None = None,
) -> dict[str, Any]:
    required = [item.strip() for item in kinds.split(",") if item.strip()] if kinds else None
    return build_experiment_artifact_health(profile_name=profile, required_kinds=required, max_age_seconds=max_age_seconds)
