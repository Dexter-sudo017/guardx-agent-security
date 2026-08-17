from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from typing import Any


def _observation_sha256(execution: dict[str, Any]) -> str:
    for phase in execution.get("phases", []):
        if not isinstance(phase, dict) or phase.get("phase") != "observe":
            continue
        metadata = phase.get("metadata") if isinstance(phase.get("metadata"), dict) else {}
        observation = str(metadata.get("observation") or "")
        if observation:
            return sha256(observation.encode("utf-8")).hexdigest()
    return sha256(b"").hexdigest()


def _provenance(execution: dict[str, Any], capability: dict[str, Any]) -> dict[str, Any]:
    tool_name = str(capability.get("tool_name") or "unknown_tool")
    runner_id = str(execution.get("runner_id") or capability.get("runner") or "unknown_runner")
    return {
        "schema_version": "guardx-runtime-provenance-v1",
        "source_refs": ["audit_store", str(execution.get("event_type") or "unknown_event")],
        "trace": {
            "trace_id": execution.get("trace_id", ""),
            "session_id": execution.get("session_id", ""),
            "execution_key": execution.get("execution_key", ""),
        },
        "executor": {
            "capability_id": f"executor_capability:{tool_name}",
            "tool_name": tool_name,
            "runner_id": runner_id,
            "side_effects": capability.get("side_effects", "unknown"),
            "dry_run": bool(capability.get("dry_run", True)),
            "rollback_supported": bool(capability.get("rollback_supported", False)),
        },
        "artifact_refs": {
            "observation_sha256": _observation_sha256(execution),
        },
    }


def _precheck(execution: dict[str, Any]) -> dict[str, Any]:
    capability = execution.get("capability") if isinstance(execution.get("capability"), dict) else {}
    return {
        "execution_key": execution.get("execution_key", ""),
        "session_id": execution.get("session_id", ""),
        "trace_id": execution.get("trace_id", ""),
        "status": execution.get("status", "unknown"),
        "rule_id": execution.get("rule_id", ""),
        "tool_name": capability.get("tool_name", "unknown_tool"),
        "runner": capability.get("runner", ""),
        "side_effects": capability.get("side_effects", "unknown"),
        "dry_run": bool(capability.get("dry_run", True)),
        "provenance": _provenance(execution, capability),
    }


def _group_key(event: dict[str, Any]) -> str:
    return str(event.get("trace_id") or event.get("session_id") or "unknown")


def build_api_sequence_audit(executions: list[dict[str, Any]], *, session_id: str | None = None, trace_id: str | None = None) -> dict[str, Any]:
    events = [_precheck(item) for item in executions]
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        groups[_group_key(event)].append(event)

    findings: list[dict[str, Any]] = []
    for key, sequence in groups.items():
        side_effects = [str(item["side_effects"]) for item in sequence]
        blocked = [item for item in sequence if item["status"] == "blocked"]
        if "registration" in side_effects and any(item in side_effects for item in ["network", "compute", "write"]):
            findings.append(
                {
                    "finding_id": f"sequence:{key}:registration-chain",
                    "risk_type": "plugin_or_tool_chain_escalation",
                    "severity": "high",
                    "sequence_key": key,
                    "evidence": side_effects,
                }
            )
        if "read" in side_effects and any(item in side_effects for item in ["write", "network"]):
            findings.append(
                {
                    "finding_id": f"sequence:{key}:read-then-exfil",
                    "risk_type": "read_then_write_or_network",
                    "severity": "medium",
                    "sequence_key": key,
                    "evidence": side_effects,
                }
            )
        if len(blocked) >= 2:
            findings.append(
                {
                    "finding_id": f"sequence:{key}:repeated-block",
                    "risk_type": "repeated_blocked_tool_attempts",
                    "severity": "medium",
                    "sequence_key": key,
                    "evidence": [item["tool_name"] for item in blocked],
                }
            )
        for event in sequence:
            if event["side_effects"] == "unknown" or not event["dry_run"]:
                findings.append(
                    {
                        "finding_id": f"sequence:{event['execution_key']}:unsafe-capability",
                        "risk_type": "unsafe_or_unknown_capability",
                        "severity": "high" if not event["dry_run"] else "medium",
                        "sequence_key": key,
                        "evidence": [event],
                    }
                )

    return {
        "schema_version": "guardx-api-sequence-audit-v1",
        "absorbed_competition_topics": ["topic8_application_security_audit", "topic1_agent_tool_misuse"],
        "scope": {"session_id": session_id, "trace_id": trace_id},
        "summary": {
            "execution_count": len(events),
            "sequence_count": len(groups),
            "finding_count": len(findings),
            "provenance_record_count": sum(1 for item in events if item.get("provenance")),
        },
        "sequences": [{"sequence_key": key, "events": value} for key, value in groups.items()],
        "findings": findings,
        "recommended_next_actions": [
            "Review high-severity sequences before allowing real tool runners.",
            "Add recurring sequence patterns to experiment suites as action or observation cases.",
            "Require explicit confirmation for read-then-write or registration-then-network chains.",
        ],
    }
