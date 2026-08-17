from __future__ import annotations

from typing import Any

from app.executor.capability_registry import default_executor_capabilities
from app.executor.runner_registry import registered_runner_ids
from app.risk_providers import default_risk_provider_registry
from app.services.supply_chain.runtime_plugins import runtime_plugin_components, runtime_plugin_findings
from app.services.supply_chain_sbom import build_supply_chain_components, summarize_supply_chain_components


HIGH_RISK_EFFECTS = {"write", "network", "compute", "registration", "unknown"}


def _capability_provenance(capability: Any) -> dict[str, Any]:
    return {
        "schema_version": "guardx-supply-chain-provenance-v1",
        "source_refs": ["src_w3c_prov", "src_slsa_provenance", "src_cyclonedx_provenance"],
        "component": {
            "component_name": capability.tool_name,
            "component_type": "executor_capability",
            "runner_id": capability.runner,
            "side_effects": capability.side_effects,
            "dry_run": capability.dry_run,
            "rollback_supported": capability.rollback_supported,
        },
        "integrity_status": "configured" if capability.constraints else "missing_constraints",
    }


def _provider_provenance(provider_id: str, manifest: Any, status: Any) -> dict[str, Any]:
    config = manifest.config or {}
    return {
        "schema_version": "guardx-supply-chain-provenance-v1",
        "source_refs": ["src_w3c_prov", "src_otel_genai", "src_slsa_provenance"],
        "component": {
            "component_name": provider_id,
            "component_type": "risk_provider",
            "deployment_modes": list(manifest.deployment_modes or []),
            "source_uri": config.get("source", ""),
        },
        "integrity_status": "ok" if status.status == "ok" and config.get("source") else "review_required",
    }


def _capability_findings() -> list[dict[str, Any]]:
    manifest = default_executor_capabilities()
    registered_runners = set(registered_runner_ids())
    findings: list[dict[str, Any]] = []
    for capability in manifest.capabilities:
        if capability.runner not in registered_runners:
            findings.append(
                {
                    "finding_id": f"supply-chain:runner:{capability.tool_name}",
                    "risk_type": "unknown_runner",
                    "severity": "high",
                    "component": capability.tool_name,
                    "evidence": [capability.runner],
                    "provenance": _capability_provenance(capability),
                }
            )
        if capability.side_effects in HIGH_RISK_EFFECTS:
            findings.append(
                {
                    "finding_id": f"supply-chain:side-effect:{capability.tool_name}",
                    "risk_type": "high_risk_tool_capability",
                    "severity": "medium" if capability.dry_run else "high",
                    "component": capability.tool_name,
                    "evidence": [capability.side_effects, f"dry_run={capability.dry_run}"],
                    "provenance": _capability_provenance(capability),
                }
            )
        if not capability.constraints:
            findings.append(
                {
                    "finding_id": f"supply-chain:constraints:{capability.tool_name}",
                    "risk_type": "missing_capability_constraints",
                    "severity": "medium",
                    "component": capability.tool_name,
                    "evidence": ["constraints empty"],
                    "provenance": _capability_provenance(capability),
                }
            )
    return findings


def _provider_findings() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    registry = default_risk_provider_registry()
    for registration in registry.registrations():
        manifest = registration.provider.metadata()
        status = registry.status_for(registration.provider_id)
        config = manifest.config or {}
        if status.status != "ok":
            findings.append(
                {
                    "finding_id": f"supply-chain:provider-health:{registration.provider_id}",
                    "risk_type": "risk_provider_degraded",
                    "severity": "medium",
                    "component": registration.provider_id,
                    "evidence": [status.status, status.message],
                    "provenance": _provider_provenance(registration.provider_id, manifest, status),
                }
            )
        if "sidecar_service" in manifest.deployment_modes and not config.get("source"):
            findings.append(
                {
                    "finding_id": f"supply-chain:provider-provenance:{registration.provider_id}",
                    "risk_type": "missing_provider_provenance",
                    "severity": "low",
                    "component": registration.provider_id,
                    "evidence": ["source/integrity metadata not declared"],
                    "provenance": _provider_provenance(registration.provider_id, manifest, status),
                }
            )
    return findings


def build_supply_chain_audit(decision_records: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    capability_findings = _capability_findings()
    provider_findings = _provider_findings()
    static_components = build_supply_chain_components()
    runtime_components = runtime_plugin_components(decision_records)
    runtime_findings = runtime_plugin_findings(runtime_components)
    findings = capability_findings + provider_findings + runtime_findings
    components = static_components + runtime_components
    component_summary = summarize_supply_chain_components(components)
    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return {
        "schema_version": "guardx-supply-chain-audit-v1",
        "absorbed_competition_topics": ["topic9_supply_chain_detection", "topic8_application_security_audit"],
        "summary": {
            "capability_count": len(default_executor_capabilities().capabilities),
            "risk_provider_count": len(default_risk_provider_registry().registrations()),
            "finding_count": len(findings),
            "severity_counts": severity_counts,
            "provenance_record_count": sum(1 for item in findings if item.get("provenance")),
            **component_summary,
        },
        "components": components,
        "findings": findings,
        "recommended_next_actions": [
            "Keep all real runners behind explicit capability manifests.",
            "Record source, version, and integrity metadata for sidecar providers and plugin tools.",
            "Require review for registration, network, write, and code-execution capabilities.",
        ],
    }
