from __future__ import annotations

from typing import Any


RUNTIME_HIGH_RISK_EFFECTS = {"write", "network", "compute", "registration", "unknown"}
RUNTIME_PLUGIN_COMPONENT = "runtime_agent_plugin_execution"


def _decision_record(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("decision_record")
    return value if isinstance(value, dict) else {}


def _lifecycle(record: dict[str, Any]) -> dict[str, Any]:
    value = _decision_record(record).get("lifecycle_report")
    return value if isinstance(value, dict) else {}


def _envelope_metadata(record: dict[str, Any]) -> dict[str, Any]:
    envelope = _decision_record(record).get("envelope")
    metadata = envelope.get("metadata") if isinstance(envelope, dict) else {}
    return metadata if isinstance(metadata, dict) else {}


def _phase_metadata(record: dict[str, Any]) -> dict[str, Any]:
    for event in _lifecycle(record).get("events", []):
        if not isinstance(event, dict):
            continue
        metadata = event.get("metadata")
        if isinstance(metadata, dict):
            return metadata
    return {}


def _provenance(
    *,
    plugin_name: str,
    source_uri: str,
    manifest_sha256: str,
    trace_id: str,
    execution_key: str,
    tool_name: str,
    side_effects: str,
    dry_run: bool,
    rollback_supported: bool,
) -> dict[str, Any]:
    return {
        "schema_version": "guardx-supply-chain-provenance-v1",
        "source_refs": ["audit_store", "src_w3c_prov", "src_slsa_provenance", "src_cyclonedx_provenance"],
        "component": {
            "component_name": plugin_name,
            "component_type": RUNTIME_PLUGIN_COMPONENT,
            "tool_name": tool_name,
            "side_effects": side_effects,
            "source_uri": source_uri,
            "manifest_sha256": manifest_sha256,
            "dry_run": dry_run,
            "rollback_supported": rollback_supported,
        },
        "trace": {"trace_id": trace_id, "execution_key": execution_key},
        "integrity_status": "observed" if source_uri and manifest_sha256 else "review_required",
    }


def _component(record: dict[str, Any]) -> dict[str, Any] | None:
    metadata = _envelope_metadata(record)
    plugin_name = str(metadata.get("plugin_name") or "").strip()
    source_uri = str(metadata.get("source_uri") or "").strip()
    manifest_sha256 = str(metadata.get("manifest_sha256") or "").strip()
    if not plugin_name and not source_uri and not manifest_sha256:
        return None
    lifecycle = _lifecycle(record)
    if not lifecycle:
        return None

    phase_metadata = _phase_metadata(record)
    capability = phase_metadata.get("capability") if isinstance(phase_metadata.get("capability"), dict) else {}
    tool_name = str(capability.get("tool_name") or "unknown_tool")
    side_effects = str(capability.get("side_effects") or "unknown")
    runner_id = str(phase_metadata.get("runner_id") or capability.get("runner") or "unknown_runner")
    dry_run = bool(capability.get("dry_run", True))
    rollback_supported = bool(capability.get("rollback_supported", False))
    constraints = capability.get("constraints") if isinstance(capability.get("constraints"), dict) else {}
    decision_record = _decision_record(record)
    trace_id = str(decision_record.get("trace_id") or metadata.get("trace_id") or "")
    execution_key = str(lifecycle.get("execution_key") or metadata.get("execution_key") or "")
    risk_flags = _risk_flags(side_effects, source_uri, manifest_sha256, dry_run)
    return {
        "component_id": f"runtime-plugin:{trace_id}:{execution_key}",
        "component_type": RUNTIME_PLUGIN_COMPONENT,
        "plugin_name": plugin_name or "unknown_plugin",
        "tool_name": tool_name,
        "runner_id": runner_id,
        "trace_id": trace_id,
        "session_id": record.get("session_id") or decision_record.get("session_id"),
        "execution_key": execution_key,
        "side_effects": side_effects,
        "source_uri": source_uri,
        "manifest_sha256": manifest_sha256,
        "constraints_present": bool(constraints),
        "constraints": constraints,
        "dry_run": dry_run,
        "rollback_supported": rollback_supported,
        "risk_flags": risk_flags,
        "provenance": _provenance(
            plugin_name=plugin_name or "unknown_plugin",
            source_uri=source_uri,
            manifest_sha256=manifest_sha256,
            trace_id=trace_id,
            execution_key=execution_key,
            tool_name=tool_name,
            side_effects=side_effects,
            dry_run=dry_run,
            rollback_supported=rollback_supported,
        ),
    }


def _risk_flags(side_effects: str, source_uri: str, manifest_sha256: str, dry_run: bool) -> list[str]:
    flags: list[str] = []
    if side_effects in RUNTIME_HIGH_RISK_EFFECTS:
        flags.append("runtime_high_risk_side_effect")
    if not source_uri:
        flags.append("missing_runtime_source_uri")
    if not manifest_sha256:
        flags.append("missing_manifest_hash")
    if not dry_run:
        flags.append("live_execution")
    return flags


def runtime_plugin_components(decision_records: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in decision_records or []:
        component = _component(record)
        component_id = str(component.get("component_id") or "") if component else ""
        if not component or component_id in seen:
            continue
        seen.add(component_id)
        components.append(component)
    return components


def runtime_plugin_findings(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = _missing_provenance_findings(components)
    by_trace: dict[str, list[dict[str, Any]]] = {}
    for component in components:
        by_trace.setdefault(str(component.get("trace_id") or ""), []).append(component)
    for trace_id, trace_components in by_trace.items():
        side_effects = {str(component.get("side_effects") or "") for component in trace_components}
        if "registration" not in side_effects or not side_effects.intersection({"write", "network", "compute"}):
            continue
        plugin_names = sorted({str(component.get("plugin_name") or "unknown_plugin") for component in trace_components})
        findings.append(
            {
                "finding_id": f"supply-chain:runtime-chain:{trace_id}",
                "risk_type": "runtime_plugin_chain_requires_review",
                "severity": "medium",
                "component": ",".join(plugin_names),
                "evidence": sorted(side_effects),
                "provenance": trace_components[0].get("provenance"),
            }
        )
    return findings


def _missing_provenance_findings(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for component in components:
        flags = component.get("risk_flags", [])
        if "missing_runtime_source_uri" not in flags and "missing_manifest_hash" not in flags:
            continue
        findings.append(
            {
                "finding_id": f"supply-chain:runtime-provenance:{component.get('component_id')}",
                "risk_type": "runtime_plugin_missing_provenance",
                "severity": "medium",
                "component": component.get("plugin_name"),
                "evidence": flags,
                "provenance": component.get("provenance"),
            }
        )
    return findings
