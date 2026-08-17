from dataclasses import dataclass
from time import monotonic
from typing import Any

from app.contracts import PluginStatus, RiskFinding
from app.risk_providers.base import RiskProviderRequest
from app.risk_providers.normalization import finding_from_score


@dataclass
class RiskProviderRuntimeState:
    failures: int = 0
    circuit_open_until: float = 0.0
    cached_health: PluginStatus | None = None
    health_cached_until: float = 0.0


def circuit_open(registration: Any, state: RiskProviderRuntimeState) -> bool:
    return monotonic() < state.circuit_open_until


def status_for_registration(registration: Any, state: RiskProviderRuntimeState) -> PluginStatus:
    if circuit_open(registration, state):
        return PluginStatus(
            provider_id=registration.provider_id,
            status="unavailable",
            deployment_mode="in_process",
            message="provider_circuit_open",
        )
    now = monotonic()
    if state.cached_health is not None and now < state.health_cached_until:
        return state.cached_health
    try:
        status = registration.provider.health()
    except Exception as exc:
        status = PluginStatus(
            provider_id=registration.provider_id,
            status="unavailable",
            deployment_mode="in_process",
            message=f"health_error:{type(exc).__name__}",
        )
    state.cached_health = status
    state.health_cached_until = now + registration.health_cache_seconds
    return status


def score_registration(registration: Any, state: RiskProviderRuntimeState, request: RiskProviderRequest) -> list[RiskFinding]:
    if circuit_open(registration, state):
        return [
            finding_from_score(
                provider_id=registration.provider_id,
                surface=request.surface,
                risk_score=0.0,
                risk_type="prompt_injection",
                confidence=0.0,
                evidence_refs=["provider_circuit_open"],
                features={"cooldown_seconds": registration.cooldown_seconds},
            )
        ]
    try:
        findings = registration.provider.score(request, request.segments)
        state.failures = 0
        return findings
    except Exception as exc:
        state.failures += 1
        if state.failures >= registration.failure_threshold:
            state.circuit_open_until = monotonic() + registration.cooldown_seconds
        return [
            finding_from_score(
                provider_id=registration.provider_id,
                surface=request.surface,
                risk_score=0.0,
                risk_type="prompt_injection",
                confidence=0.0,
                evidence_refs=[f"provider_error:{type(exc).__name__}"],
                features={
                    "error": str(exc),
                    "failure_count": state.failures,
                    "circuit_open": circuit_open(registration, state),
                },
            )
        ]
