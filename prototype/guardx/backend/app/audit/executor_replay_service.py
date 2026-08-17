from typing import Any

from app.audit.executor_replay import executor_replay_from_decision_records, executor_replay_from_trace_events


def load_executor_replay(
    audit_store: Any,
    *,
    session_id: str | None = None,
    trace_id: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    trace_events = audit_store.trace_events(session_id=session_id, trace_id=trace_id, limit=limit)
    executions = executor_replay_from_trace_events(trace_events)
    if not executions:
        records = audit_store.decision_records(session_id=session_id, trace_id=trace_id, limit=limit)
        executions = executor_replay_from_decision_records(records)
    return executions
