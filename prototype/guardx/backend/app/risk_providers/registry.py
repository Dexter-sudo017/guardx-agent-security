import json
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.contracts import PluginStatus, RiskFinding
from app.risk_providers.base import RiskProvider, RiskProviderRequest
from app.risk_providers.provider_runtime import RiskProviderRuntimeState, score_registration, status_for_registration


PROJECT_ROOT = Path(__file__).resolve().parents[5]
RISK_PROVIDER_REGISTRY_PATH = PROJECT_ROOT / "configs" / "risk_provider_registry.json"


@dataclass(frozen=True)
class RiskProviderRegistration:
    provider_id: str
    provider: RiskProvider
    surfaces: tuple[str, ...]
    enabled: bool = True
    failure_threshold: int = 2
    cooldown_seconds: float = 30.0
    health_cache_seconds: float = 5.0

    def accepts(self, surface: str) -> bool:
        return self.enabled and ("*" in self.surfaces or surface in self.surfaces)


class RiskProviderRegistry:
    def __init__(self, registrations: list[RiskProviderRegistration] | None = None) -> None:
        self._registrations: dict[str, RiskProviderRegistration] = {}
        self._runtime_state: dict[str, RiskProviderRuntimeState] = {}
        for registration in registrations or []:
            self.register(
                registration.provider,
                surfaces=registration.surfaces,
                enabled=registration.enabled,
                provider_id=registration.provider_id,
                failure_threshold=registration.failure_threshold,
                cooldown_seconds=registration.cooldown_seconds,
                health_cache_seconds=registration.health_cache_seconds,
            )

    def register(
        self,
        provider: RiskProvider,
        *,
        surfaces: tuple[str, ...] | list[str] = ("*",),
        enabled: bool = True,
        provider_id: str | None = None,
        failure_threshold: int = 2,
        cooldown_seconds: float = 30.0,
        health_cache_seconds: float = 5.0,
    ) -> None:
        resolved_id = provider_id or provider.provider_id
        self._registrations[resolved_id] = RiskProviderRegistration(
            provider_id=resolved_id,
            provider=provider,
            surfaces=tuple(str(surface) for surface in surfaces),
            enabled=enabled,
            failure_threshold=max(1, int(failure_threshold)),
            cooldown_seconds=max(0.0, float(cooldown_seconds)),
            health_cache_seconds=max(0.0, float(health_cache_seconds)),
        )
        self._runtime_state.setdefault(resolved_id, RiskProviderRuntimeState())

    def provider_ids(self) -> list[str]:
        return sorted(self._registrations)

    def registrations(self) -> list[RiskProviderRegistration]:
        return [self._registrations[provider_id] for provider_id in self.provider_ids()]

    def enabled_for_surface(self, surface: str) -> list[RiskProviderRegistration]:
        if not _risk_providers_enabled():
            return []
        return [item for item in self._registrations.values() if item.accepts(surface) and _provider_enabled_by_env(item.provider_id)]

    def _state(self, registration: RiskProviderRegistration) -> RiskProviderRuntimeState:
        return self._runtime_state.setdefault(registration.provider_id, RiskProviderRuntimeState())

    def status_for(self, provider_id: str) -> PluginStatus:
        registration = self._registrations[provider_id]
        return status_for_registration(registration, self._state(registration))

    def score(self, request: RiskProviderRequest) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        for registration in self.enabled_for_surface(request.surface):
            findings.extend(score_registration(registration, self._state(registration), request))
        return findings


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _env_enabled(name: str, default: bool = True) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _risk_providers_enabled() -> bool:
    return _env_enabled("GUARDX_RISK_PROVIDERS_ENABLED", default=True)


def _provider_enabled_by_env(provider_id: str) -> bool:
    env_name = f"GUARDX_RISK_PROVIDER_{provider_id.upper().replace('-', '_')}_ENABLED"
    return _env_enabled(env_name, default=True)


def _make_provider(provider_id: str, plugin_config_path: str | None) -> RiskProvider | None:
    if provider_id != "srtp_embedguard":
        return None
    from app.plugins.srtp_embedguard import make_srtp_embedguard_provider

    plugin_config = _read_json(PROJECT_ROOT / plugin_config_path) if plugin_config_path else {}
    deployment = plugin_config.get("deployment") if isinstance(plugin_config.get("deployment"), dict) else {}
    mode = str(deployment.get("mode") or "in_process")
    sidecar = deployment.get("sidecar_service") if isinstance(deployment.get("sidecar_service"), dict) else {}
    return make_srtp_embedguard_provider(
        mode,
        base_url=str(sidecar.get("base_url") or ""),
        timeout_seconds=int(sidecar.get("timeout_seconds") or 30),
    )


@lru_cache(maxsize=1)
def default_risk_provider_registry() -> RiskProviderRegistry:
    raw = _read_json(RISK_PROVIDER_REGISTRY_PATH)
    registry = RiskProviderRegistry()
    for item in raw.get("providers") or []:
        if not isinstance(item, dict):
            continue
        provider_id = str(item.get("provider_id") or "")
        provider = _make_provider(provider_id, item.get("plugin_config"))
        if provider is None:
            continue
        runtime = item.get("runtime") if isinstance(item.get("runtime"), dict) else {}
        registry.register(
            provider,
            provider_id=provider_id,
            surfaces=[str(surface) for surface in item.get("surfaces") or ["*"]],
            enabled=bool(item.get("enabled", True)),
            failure_threshold=int(runtime.get("failure_threshold") or 2),
            cooldown_seconds=float(runtime.get("cooldown_seconds") or 30),
            health_cache_seconds=float(runtime.get("health_cache_seconds") or 5),
        )
    return registry


def score_registered_risk_providers(request: RiskProviderRequest, registry: RiskProviderRegistry | None = None) -> list[RiskFinding]:
    return (registry or default_risk_provider_registry()).score(request)
