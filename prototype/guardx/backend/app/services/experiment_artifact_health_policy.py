import json
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field


PROJECT_ROOT = Path(__file__).resolve().parents[5]
ARTIFACT_HEALTH_POLICY_PATH = PROJECT_ROOT / "configs" / "experiment_artifact_health_policy.json"
DEFAULT_REQUIRED_KINDS = ["model_recommendation_gate", "real_model_matrix_plan", "model_matrix"]


class ArtifactHealthProfile(BaseModel):
    name: str
    stage: str = "local_dev"
    description: str = ""
    required_kinds: list[str] = Field(default_factory=lambda: list(DEFAULT_REQUIRED_KINDS))
    max_age_seconds: int = 7 * 24 * 60 * 60


class ArtifactHealthPolicyManifest(BaseModel):
    schema_version: str = "guardx-experiment-artifact-health-policy-v1"
    default_profile: str = "local_dev"
    profiles: dict[str, ArtifactHealthProfile] = Field(default_factory=dict)


def _profile_from_payload(name: str, payload: dict) -> ArtifactHealthProfile:
    return ArtifactHealthProfile(
        name=name,
        stage=str(payload.get("stage") or name),
        description=str(payload.get("description") or ""),
        required_kinds=[str(item) for item in payload.get("required_kinds") or DEFAULT_REQUIRED_KINDS],
        max_age_seconds=max(0, int(payload.get("max_age_seconds") or 0)) or 7 * 24 * 60 * 60,
    )


@lru_cache(maxsize=1)
def load_artifact_health_policy() -> ArtifactHealthPolicyManifest:
    if not ARTIFACT_HEALTH_POLICY_PATH.exists():
        default = ArtifactHealthProfile(name="local_dev")
        return ArtifactHealthPolicyManifest(profiles={default.name: default})
    try:
        raw = json.loads(ARTIFACT_HEALTH_POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raw = {}
    profiles = {
        str(name): _profile_from_payload(str(name), payload if isinstance(payload, dict) else {})
        for name, payload in (raw.get("profiles") or {}).items()
    }
    default_name = str(raw.get("default_profile") or "local_dev")
    if default_name not in profiles:
        profiles[default_name] = ArtifactHealthProfile(name=default_name)
    return ArtifactHealthPolicyManifest(
        schema_version=str(raw.get("schema_version") or "guardx-experiment-artifact-health-policy-v1"),
        default_profile=default_name,
        profiles=profiles,
    )


def resolve_artifact_health_profile(profile_name: str | None = None) -> ArtifactHealthProfile:
    manifest = load_artifact_health_policy()
    requested = (profile_name or manifest.default_profile).strip() or manifest.default_profile
    return manifest.profiles.get(requested) or manifest.profiles[manifest.default_profile]
