from __future__ import annotations

from typing import Any

from app.executor.capability_registry import default_executor_capabilities
from app.executor.runner_registry import registered_runner_ids
from app.risk_providers import default_risk_provider_registry


HIGH_RISK_EFFECTS = {"write", "network", "compute", "registration", "unknown"}


def _capability_component(capability: Any, registered_runners: set[str]) -> dict[str, Any]:
    constraints = capability.constraints or {}
    return {
        "component_id": f"executor:{capability.tool_name}",
        "component_type": "agent_tool_capability",
        "tool_name": capability.tool_name,
        "runner_id": capability.runner,
        "runner_registered": capability.runner in registered_runners,
        "side_effects": capability.side_effects,
        "source_uri": f"configs/executor_capabilities.json#capabilities/{capability.tool_name}",
        "constraints_present": bool(constraints),
        "constraints": constraints,
        "dry_run": capability.dry_run,
        "rollback_supported": capability.rollback_supported,
        "risk_flags": _capability_flags(capability, registered_runners),
    }


def _capability_flags(capability: Any, registered_runners: set[str]) -> list[str]:
    flags: list[str] = []
    if capability.side_effects in HIGH_RISK_EFFECTS:
        flags.append("high_risk_side_effect")
    if capability.runner not in registered_runners:
        flags.append("unknown_runner")
    if not capability.constraints:
        flags.append("missing_constraints")
    if capability.side_effects in {"write", "network", "registration"} and not capability.rollback_supported:
        flags.append("no_rollback_for_sensitive_effect")
    if not capability.dry_run:
        flags.append("live_execution")
    return flags


def _provider_component(registration: Any) -> dict[str, Any]:
    manifest = registration.provider.metadata()
    status = default_risk_provider_registry().status_for(registration.provider_id)
    config = manifest.config or {}
    return {
        "component_id": f"risk_provider:{registration.provider_id}",
        "component_type": "risk_provider_plugin",
        "provider_id": registration.provider_id,
        "deployment_modes": list(manifest.deployment_modes or []),
        "runtime_status": status.status,
        "source_uri": config.get("source", ""),
        "constraints_present": bool(config),
        "dry_run": None,
        "rollback_supported": None,
        "risk_flags": _provider_flags(manifest, status, config),
    }


def _provider_flags(manifest: Any, status: Any, config: dict[str, Any]) -> list[str]:
    flags: list[str] = []
    if status.status != "ok":
        flags.append("provider_degraded")
    if "sidecar_service" in manifest.deployment_modes and not config.get("source"):
        flags.append("missing_provider_source")
    return flags


def build_supply_chain_components() -> list[dict[str, Any]]:
    manifest = default_executor_capabilities()
    registered_runners = set(registered_runner_ids())
    components = [_capability_component(capability, registered_runners) for capability in manifest.capabilities]
    components.extend(_provider_component(registration) for registration in default_risk_provider_registry().registrations())
    return components


def summarize_supply_chain_components(components: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "component_count": len(components),
        "tool_component_count": sum(1 for item in components if item.get("component_type") == "agent_tool_capability"),
        "provider_component_count": sum(1 for item in components if item.get("component_type") == "risk_provider_plugin"),
        "runtime_plugin_component_count": sum(1 for item in components if item.get("component_type") == "runtime_agent_plugin_execution"),
        "high_risk_component_count": sum(1 for item in components if item.get("risk_flags")),
        "missing_constraints_count": sum(1 for item in components if not item.get("constraints_present")),
        "live_execution_count": sum(1 for item in components if item.get("dry_run") is False),
    }
