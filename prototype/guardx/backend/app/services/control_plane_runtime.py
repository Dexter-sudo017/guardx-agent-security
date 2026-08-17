from typing import Any

from app.executor.capability_registry import default_executor_capabilities
from app.executor.runner_registry import registered_runner_ids
from app.executor.runtime_policy import default_executor_runtime_policy
from app.policy import load_policy_profiles
from app.risk_providers import default_risk_provider_registry


def control_plane_summary() -> dict[str, Any]:
    profiles = load_policy_profiles()
    provider_registry = default_risk_provider_registry()
    providers = []
    for registration in provider_registry.registrations():
        status = provider_registry.status_for(registration.provider_id).model_dump()
        manifest = registration.provider.metadata().model_dump()
        providers.append(
            {
                "provider_id": registration.provider_id,
                "enabled": registration.enabled,
                "surfaces": list(registration.surfaces),
                "runtime": {
                    "failure_threshold": registration.failure_threshold,
                    "cooldown_seconds": registration.cooldown_seconds,
                    "health_cache_seconds": registration.health_cache_seconds,
                },
                "status": status,
                "manifest": manifest,
            }
        )
    return {
        "schema_version": "guardx-control-plane-v1",
        "policy_profiles": {
            "schema_version": profiles.schema_version,
            "default_profile": profiles.default_profile,
            "profiles": {
                name: {
                    "thresholds": profile.thresholds.model_dump(),
                    "rules": profile.rules.model_dump(),
                    "required_guards": profile.required_guards,
                    "audit_level": profile.audit_level,
                }
                for name, profile in profiles.profiles.items()
            },
        },
        "risk_providers": providers,
        "executor_capabilities": default_executor_capabilities().model_dump(),
        "executor_runtime_policy": default_executor_runtime_policy().model_dump(),
        "executor_runners": registered_runner_ids(),
    }
