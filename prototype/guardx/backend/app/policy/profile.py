import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.config import SETTINGS
from app.contracts import PolicyDecision


PROJECT_ROOT = Path(__file__).resolve().parents[5]
POLICY_PROFILES_PATH = PROJECT_ROOT / "configs" / "policy_profiles.json"


class PolicyProfileThresholds(BaseModel):
    medium: float = SETTINGS.thresholds.medium
    high: float = SETTINGS.thresholds.high
    critical: float = SETTINGS.thresholds.critical


class PolicyProfileRules(BaseModel):
    provider_weights: dict[str, float] = Field(default_factory=dict)
    risk_type_weights: dict[str, float] = Field(default_factory=dict)
    surface_weights: dict[str, float] = Field(default_factory=dict)


class PolicyProfile(BaseModel):
    name: str
    thresholds: PolicyProfileThresholds = Field(default_factory=PolicyProfileThresholds)
    required_guards: list[str] = Field(default_factory=list)
    audit_level: str = "summary"
    rules: PolicyProfileRules = Field(default_factory=PolicyProfileRules)


class PolicyProfileRegistry(BaseModel):
    schema_version: str = "guardx-policy-profiles-v1"
    default_profile: str = "v5l"
    profiles: dict[str, PolicyProfile] = Field(default_factory=dict)


def _profile_from_payload(name: str, payload: dict[str, Any]) -> PolicyProfile:
    return PolicyProfile(
        name=name,
        thresholds=PolicyProfileThresholds.model_validate(payload.get("thresholds") or {}),
        required_guards=[str(item) for item in payload.get("required_guards") or []],
        audit_level=str(payload.get("audit_level") or "summary"),
        rules=PolicyProfileRules.model_validate(payload.get("rules") or {}),
    )


@lru_cache(maxsize=1)
def load_policy_profiles() -> PolicyProfileRegistry:
    if not POLICY_PROFILES_PATH.exists():
        return PolicyProfileRegistry(
            profiles={
                "v5l": PolicyProfile(
                    name="v5l",
                    thresholds=PolicyProfileThresholds(),
                    required_guards=["input_guard", "context_guard", "srtp_embedguard", "output_guard"],
                )
            }
        )
    try:
        raw = json.loads(POLICY_PROFILES_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raw = {}
    profiles = {
        str(name): _profile_from_payload(str(name), payload if isinstance(payload, dict) else {})
        for name, payload in (raw.get("profiles") or {}).items()
    }
    default_profile = str(raw.get("default_profile") or "v5l")
    if default_profile not in profiles:
        profiles[default_profile] = PolicyProfile(name=default_profile, thresholds=PolicyProfileThresholds())
    return PolicyProfileRegistry(
        schema_version=str(raw.get("schema_version") or "guardx-policy-profiles-v1"),
        default_profile=default_profile,
        profiles=profiles,
    )


def resolve_policy_profile(metadata: dict[str, Any] | None = None) -> PolicyProfile:
    registry = load_policy_profiles()
    requested = str((metadata or {}).get("policy_profile") or registry.default_profile)
    return registry.profiles.get(requested) or registry.profiles[registry.default_profile]


def apply_policy_profile(decision: PolicyDecision, profile: PolicyProfile) -> PolicyDecision:
    constraints = {
        **decision.constraints,
        "policy_profile": profile.name,
        "policy_thresholds": profile.thresholds.model_dump(),
        "policy_rules": profile.rules.model_dump(),
    }
    required_guards = list(dict.fromkeys([*decision.required_guards, *profile.required_guards]))
    return PolicyDecision(
        route=decision.route,
        action=decision.action,
        risk_score=decision.risk_score,
        reasons=decision.reasons,
        constraints=constraints,
        required_guards=required_guards,
        audit_level=profile.audit_level if decision.audit_level == "summary" else decision.audit_level,
    )


def weighted_finding_risk_score(findings: list[Any], profile: PolicyProfile) -> float:
    scores: list[float] = []
    for finding in findings:
        provider_id = str(getattr(finding, "provider_id", ""))
        risk_type = str(getattr(finding, "risk_type", ""))
        surface = str(getattr(finding, "surface", ""))
        provider_weight = float(profile.rules.provider_weights.get(provider_id, 1.0))
        risk_type_weight = float(profile.rules.risk_type_weights.get(risk_type, 1.0))
        surface_weight = float(profile.rules.surface_weights.get(surface, 1.0))
        scores.append(float(getattr(finding, "risk_score", 0.0)) * provider_weight * risk_type_weight * surface_weight)
    return min(1.0, max(scores or [0.0]))


def effective_policy_risk_score(base_score: float, findings: list[Any], profile: PolicyProfile) -> float:
    return min(1.0, max(float(base_score), weighted_finding_risk_score(findings, profile)))
