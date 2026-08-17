from typing import Any

from app.services.executor_replay_details import finalize_executor_replay_executions


def _phase_from_snapshot(snapshot: dict[str, Any], lifecycle_event: dict[str, Any]) -> str:
    return str(snapshot.get("execution_phase") or lifecycle_event.get("phase") or "")


def _phase_item(
    *,
    phase: str | None,
    lifecycle_event: dict[str, Any],
    span_id: str | None,
    created_at: str | None,
) -> dict[str, Any]:
    return {
        "phase": phase,
        "status": lifecycle_event.get("status"),
        "span_id": span_id,
        "input_ref": lifecycle_event.get("input_ref"),
        "output_ref": lifecycle_event.get("output_ref"),
        "error": lifecycle_event.get("error"),
        "latency_ms": lifecycle_event.get("latency_ms", 0.0),
        "metadata": lifecycle_event.get("metadata", {}),
        "created_at": created_at,
    }


def executor_replay_from_trace_events(trace_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in trace_events:
        trace_event = row.get("trace_event")
        if not isinstance(trace_event, dict):
            continue
        snapshot = trace_event.get("risk_snapshot")
        if not isinstance(snapshot, dict):
            continue
        lifecycle_event = snapshot.get("execution_lifecycle_event")
        execution_key = snapshot.get("execution_key")
        if not isinstance(lifecycle_event, dict) or not execution_key:
            continue
        group = grouped.setdefault(
            str(execution_key),
            {
                "execution_key": str(execution_key),
                "trace_id": trace_event.get("trace_id"),
                "session_id": row.get("session_id"),
                "event_type": row.get("event_type"),
                "phases": [],
            },
        )
        group["phases"].append(
            _phase_item(
                phase=_phase_from_snapshot(snapshot, lifecycle_event),
                lifecycle_event=lifecycle_event,
                span_id=trace_event.get("span_id"),
                created_at=row.get("created_at"),
            )
        )
    return finalize_executor_replay_executions(list(grouped.values()))


def executor_replay_from_decision_records(decision_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    executions: list[dict[str, Any]] = []
    for row in decision_records:
        decision_record = row.get("decision_record")
        if not isinstance(decision_record, dict):
            continue
        lifecycle_report = decision_record.get("lifecycle_report")
        if not isinstance(lifecycle_report, dict):
            continue
        phases = [
            _phase_item(
                phase=lifecycle_event.get("phase"),
                lifecycle_event=lifecycle_event,
                span_id=None,
                created_at=row.get("created_at"),
            )
            for lifecycle_event in lifecycle_report.get("events", [])
            if isinstance(lifecycle_event, dict)
        ]
        executions.append(
            {
                "execution_key": lifecycle_report.get("execution_key", ""),
                "trace_id": decision_record.get("trace_id"),
                "session_id": row.get("session_id"),
                "event_type": row.get("event_type"),
                "rollback_required": bool(lifecycle_report.get("rollback_required", False)),
                "rollback_completed": bool(lifecycle_report.get("rollback_completed", False)),
                "phases": phases,
            }
        )
    return finalize_executor_replay_executions(executions)
