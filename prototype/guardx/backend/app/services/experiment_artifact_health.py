from time import time
from typing import Any

from app.services import experiment_artifact_index
from app.services.experiment_artifact_health_policy import resolve_artifact_health_profile


DEFAULT_REQUIRED_KINDS = ["model_recommendation_gate", "real_model_matrix_plan", "model_matrix"]


def build_experiment_artifact_health(
    *,
    profile_name: str | None = None,
    required_kinds: list[str] | None = None,
    max_age_seconds: int | None = None,
) -> dict[str, Any]:
    profile = resolve_artifact_health_profile(profile_name)
    now = time()
    required = required_kinds or profile.required_kinds or DEFAULT_REQUIRED_KINDS
    max_age = int(max_age_seconds if max_age_seconds is not None else profile.max_age_seconds)
    items: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    stale: list[str] = []
    failed: list[str] = []
    for kind in required:
        index = experiment_artifact_index.list_experiment_artifacts(limit=1, kind=kind)
        artifact = (index.get("artifacts") or [None])[0]
        if not artifact:
            missing.append(kind)
            items[kind] = {"available": False}
            continue
        age_seconds = max(0, int(now - float(artifact.get("modified_at") or now)))
        is_stale = age_seconds > max_age
        if is_stale:
            stale.append(kind)
        metadata = artifact.get("metadata") or {}
        is_failed = metadata.get("passed") is False
        if is_failed:
            failed.append(kind)
        items[kind] = {
            "available": True,
            "stale": is_stale,
            "failed": is_failed,
            "name": artifact.get("name"),
            "kind": artifact.get("kind"),
            "modified_at": artifact.get("modified_at"),
            "age_seconds": age_seconds,
            "metadata": metadata,
        }
    state = "missing" if missing else "stale" if stale else "failed" if failed else "ready"
    return {
        "schema_version": "guardx-experiment-artifact-health-v1",
        "state": state,
        "policy_profile": profile.name,
        "stage": profile.stage,
        "policy": {
            "description": profile.description,
            "required_kinds": profile.required_kinds,
            "max_age_seconds": profile.max_age_seconds,
        },
        "overrides": {
            "required_kinds": required_kinds,
            "max_age_seconds": max_age_seconds,
        },
        "required_kinds": required,
        "max_age_seconds": max_age,
        "missing_kinds": missing,
        "stale_kinds": stale,
        "failed_kinds": failed,
        "items": items,
    }
