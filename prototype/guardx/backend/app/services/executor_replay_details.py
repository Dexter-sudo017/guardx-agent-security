import hashlib
from typing import Any


PHASE_ORDER = {"precheck": 0, "execute": 1, "observe": 2, "rollback": 3}


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _execution_status(phases: list[dict[str, Any]]) -> str:
    if any(phase.get("phase") == "observe" and phase.get("status") == "success" for phase in phases):
        return "success"
    statuses = {str(phase.get("status")) for phase in phases}
    if "timeout" in statuses:
        return "timeout"
    if "blocked" in statuses:
        return "blocked"
    if "failed" in statuses or "rolled_back" in statuses:
        return "failed"
    return "success" if phases else "unknown"


def _precheck_summary(phases: list[dict[str, Any]]) -> dict[str, Any]:
    precheck = next((phase for phase in phases if phase.get("phase") == "precheck"), {})
    metadata = precheck.get("metadata") if isinstance(precheck.get("metadata"), dict) else {}
    capability = metadata.get("capability") if isinstance(metadata.get("capability"), dict) else {}
    return {
        "rule_id": metadata.get("rule_id", ""),
        "runner_id": metadata.get("runner_id", ""),
        "runner_fallback_used": bool(metadata.get("runner_fallback_used", False)),
        "capability": capability,
        "runtime_policy": metadata.get("runtime_policy", {}) if isinstance(metadata.get("runtime_policy"), dict) else {},
    }


def _unique_refs(phases: list[dict[str, Any]], key: str) -> list[str]:
    refs = []
    seen = set()
    for phase in phases:
        value = phase.get(key)
        if value and value not in seen:
            refs.append(str(value))
            seen.add(value)
    return refs


def _phase_statuses(phases: list[dict[str, Any]]) -> dict[str, list[str]]:
    statuses: dict[str, list[str]] = {}
    for phase in phases:
        statuses.setdefault(str(phase.get("phase") or "unknown"), []).append(str(phase.get("status") or "unknown"))
    return statuses


def _phase_errors(phases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "phase": phase.get("phase"),
            "status": phase.get("status"),
            "error": phase.get("error"),
            "created_at": phase.get("created_at"),
        }
        for phase in phases
        if phase.get("error")
    ]


def _observation_hash(phases: list[dict[str, Any]]) -> str:
    for phase in phases:
        metadata = phase.get("metadata") if isinstance(phase.get("metadata"), dict) else {}
        observation = metadata.get("observation")
        if isinstance(observation, str) and observation:
            return _sha256_text(observation)
    return ""


def _phase_chain_hash(phases: list[dict[str, Any]]) -> str:
    chain = "|".join(
        ":".join(
            [
                str(phase.get("phase") or ""),
                str(phase.get("status") or ""),
                str(phase.get("input_ref") or ""),
                str(phase.get("output_ref") or ""),
                str(phase.get("error") or ""),
            ]
        )
        for phase in phases
    )
    return _sha256_text(chain) if chain else ""


def _rollback_required(phases: list[dict[str, Any]]) -> bool:
    failure_statuses = {"failed", "timeout"}
    has_execute_failure = any(
        phase.get("phase") == "execute" and phase.get("status") in failure_statuses for phase in phases
    )
    if not has_execute_failure:
        return False
    for phase in phases:
        if phase.get("phase") != "rollback":
            continue
        metadata = phase.get("metadata") if isinstance(phase.get("metadata"), dict) else {}
        if metadata.get("reason") in {"no_rollback_required", "no_side_effects_before_allow"}:
            return False
    return True


def _replay_provenance(execution: dict[str, Any]) -> dict[str, Any]:
    capability = execution.get("capability") if isinstance(execution.get("capability"), dict) else {}
    phases = execution.get("phases") if isinstance(execution.get("phases"), list) else []
    return {
        "schema_version": "guardx-executor-replay-provenance-v1",
        "source_standards": ["src_w3c_prov", "src_opentelemetry_genai", "src_slsa_provenance"],
        "activity_type": "agent_tool_execution",
        "execution_key": execution.get("execution_key", ""),
        "trace_id": execution.get("trace_id"),
        "session_id": execution.get("session_id"),
        "tool_name": capability.get("tool_name", ""),
        "runner_id": execution.get("runner_id", ""),
        "side_effects": capability.get("side_effects", "unknown"),
        "dry_run": bool(capability.get("dry_run", False)),
        "rollback_supported": bool(capability.get("rollback_supported", False)),
        "input_refs": execution.get("input_refs") if isinstance(execution.get("input_refs"), list) else [],
        "output_refs": execution.get("output_refs") if isinstance(execution.get("output_refs"), list) else [],
        "observation_sha256": _observation_hash(phases),
        "phase_chain_sha256": _phase_chain_hash(phases),
    }


def finalize_executor_replay_executions(executions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for execution in executions:
        execution["phases"].sort(key=lambda item: PHASE_ORDER.get(str(item.get("phase")), 99))
        execution["status"] = _execution_status(execution["phases"])
        execution["phase_count"] = len(execution["phases"])
        execution.update(_precheck_summary(execution["phases"]))
        execution["phase_statuses"] = _phase_statuses(execution["phases"])
        execution["phase_errors"] = _phase_errors(execution["phases"])
        execution["input_refs"] = _unique_refs(execution["phases"], "input_ref")
        execution["output_refs"] = _unique_refs(execution["phases"], "output_ref")
        execution.setdefault("rollback_required", _rollback_required(execution["phases"]))
        execution.setdefault(
            "rollback_completed",
            any(phase.get("phase") == "rollback" and phase.get("status") == "rolled_back" for phase in execution["phases"]),
        )
        execution["provenance"] = _replay_provenance(execution)
    executions.sort(key=lambda item: str(item.get("execution_key")))
    return executions
