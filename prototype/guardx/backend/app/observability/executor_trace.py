from typing import Any

from app.contracts import ExecutionLifecycleReport
from app.observability.trace import make_trace_event


def trace_events_for_executor_lifecycle(
    *,
    trace_id: str,
    payload_ref: str,
    lifecycle_report: ExecutionLifecycleReport,
    metadata: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, lifecycle_event in enumerate(lifecycle_report.events):
        trace_event = make_trace_event(
            trace_id=trace_id,
            stage="executor",
            payload_ref=payload_ref,
            metadata=metadata,
            error=lifecycle_event.error,
            span_id=f"executor-{lifecycle_event.phase}-{index}",
        )
        trace_event.risk_snapshot["execution_key"] = lifecycle_report.execution_key
        trace_event.risk_snapshot["execution_phase"] = lifecycle_event.phase
        trace_event.risk_snapshot["execution_lifecycle_event"] = lifecycle_event.model_dump()
        events.append(trace_event.model_dump())
    return events
