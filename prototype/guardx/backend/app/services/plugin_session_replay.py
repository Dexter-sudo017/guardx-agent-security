from __future__ import annotations

from collections import Counter
from typing import Any


PLUGIN_SCOPE = "plugin_registration_execute_observe"


def _source_scheme(source_uri: str) -> str:
    if "://" not in source_uri:
        return "unknown"
    return source_uri.split("://", 1)[0] or "unknown"


def _decision_record(row: dict[str, Any]) -> dict[str, Any]:
    value = row.get("decision_record")
    return value if isinstance(value, dict) else {}


def _metadata(row: dict[str, Any]) -> dict[str, Any]:
    record = _decision_record(row)
    envelope = record.get("envelope") if isinstance(record.get("envelope"), dict) else {}
    metadata = envelope.get("metadata") if isinstance(envelope.get("metadata"), dict) else {}
    return metadata


def _is_plugin_record(row: dict[str, Any]) -> bool:
    metadata = _metadata(row)
    return bool(
        metadata.get("plugin_name")
        or metadata.get("source_uri")
        or metadata.get("manifest_sha256")
        or metadata.get("provenance_scope") == PLUGIN_SCOPE
    )


def _route(record: dict[str, Any]) -> str:
    decision = record.get("policy_decision") if isinstance(record.get("policy_decision"), dict) else {}
    return str(decision.get("route") or "unknown")


def _record_stage(row: dict[str, Any]) -> str:
    record = _decision_record(row)
    metadata = _metadata(row)
    surface = str(metadata.get("surface") or record.get("surface") or row.get("event_type") or "")
    if row.get("event_type") == "action_guard_observation" or surface == "tool_output":
        return "observe"
    if surface in {"plugin", "tool_registration"}:
        return "register"
    if surface in {"tool_call", "agent_tool"}:
        return "execute"
    return "unknown"


def _execution_digest(execution: dict[str, Any]) -> dict[str, Any]:
    provenance = execution.get("provenance") if isinstance(execution.get("provenance"), dict) else {}
    capability = execution.get("capability") if isinstance(execution.get("capability"), dict) else {}
    return {
        "execution_key": execution.get("execution_key", ""),
        "tool_name": provenance.get("tool_name") or capability.get("tool_name") or "unknown_tool",
        "runner_id": provenance.get("runner_id") or execution.get("runner_id") or "",
        "side_effects": provenance.get("side_effects") or capability.get("side_effects") or "unknown",
        "status": execution.get("status", "unknown"),
        "phase_statuses": execution.get("phase_statuses", {}),
        "phase_chain_sha256": provenance.get("phase_chain_sha256", ""),
        "observation_sha256": provenance.get("observation_sha256", ""),
    }


def build_plugin_session_replay(
    decision_records: list[dict[str, Any]],
    executions: list[dict[str, Any]],
    *,
    session_id: str | None = None,
    trace_id: str | None = None,
) -> dict[str, Any]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in decision_records:
        if not _is_plugin_record(row):
            continue
        record = _decision_record(row)
        metadata = _metadata(row)
        key = str(record.get("trace_id") or metadata.get("trace_id") or row.get("trace_id") or "unknown")
        session = grouped.setdefault(
            key,
            {
                "trace_id": key,
                "session_id": row.get("session_id") or metadata.get("session_id") or session_id,
                "plugin_name": metadata.get("plugin_name") or "unknown_plugin",
                "source_uri": metadata.get("source_uri") or "",
                "manifest_sha256": metadata.get("manifest_sha256") or "",
                "stages": {},
                "records": [],
            },
        )
        stage = _record_stage(row)
        session["stages"][stage] = {
            "route": _route(record),
            "event_type": row.get("event_type", ""),
            "execution_key": metadata.get("execution_key", ""),
        }
        session["records"].append(
            {
                "stage": stage,
                "route": _route(record),
                "event_type": row.get("event_type", ""),
                "created_at": row.get("created_at", ""),
            }
        )
    for execution in executions:
        key = str(execution.get("trace_id") or "")
        if key not in grouped:
            continue
        grouped[key].setdefault("executions", []).append(_execution_digest(execution))
    sessions = [_finalize_session(item) for item in grouped.values()]
    route_counts = Counter(route for item in sessions for route in item.get("stage_routes", {}).values())
    source_scheme_counts = Counter(str(item.get("source_scheme") or "unknown") for item in sessions)
    return {
        "schema_version": "guardx-plugin-session-replay-v1",
        "scope": {"session_id": session_id, "trace_id": trace_id},
        "summary": {
            "session_count": len(sessions),
            "plugin_count": len({item.get("plugin_name") for item in sessions}),
            "with_manifest_hash_count": sum(1 for item in sessions if item.get("manifest_sha256")),
            "with_source_uri_count": sum(1 for item in sessions if item.get("source_uri")),
            "review_or_block_stage_count": sum(count for route, count in route_counts.items() if route in {"review", "block"}),
            "route_counts": dict(route_counts),
            "source_scheme_counts": dict(source_scheme_counts),
        },
        "sessions": sessions,
    }


def _finalize_session(session: dict[str, Any]) -> dict[str, Any]:
    stages = session.get("stages") if isinstance(session.get("stages"), dict) else {}
    executions = session.get("executions") if isinstance(session.get("executions"), list) else []
    stage_routes = {stage: str(value.get("route") or "unknown") for stage, value in stages.items() if isinstance(value, dict)}
    side_effects = sorted({str(item.get("side_effects") or "unknown") for item in executions})
    risk_flags = []
    if "register" in stages and any(effect in side_effects for effect in {"write", "network", "compute"}):
        risk_flags.append("registration_followed_by_side_effect")
    if any(route in {"review", "block"} for route in stage_routes.values()):
        risk_flags.append("stage_requires_review")
    if not session.get("source_uri") or not session.get("manifest_sha256"):
        risk_flags.append("missing_plugin_provenance")
    return {
        **session,
        "source_scheme": _source_scheme(str(session.get("source_uri") or "")),
        "stage_routes": stage_routes,
        "execution_count": len(executions),
        "side_effects": side_effects,
        "risk_flags": risk_flags,
    }
