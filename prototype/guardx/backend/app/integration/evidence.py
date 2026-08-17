from __future__ import annotations

from copy import deepcopy
from typing import Any, Protocol


class ExecutorEvidenceSink(Protocol):
    def append(self, *, session_id: str, event: dict[str, Any]) -> str: ...
    def session_events(self, *, session_id: str) -> list[dict[str, Any]]: ...


class InMemoryExecutorEvidenceSink:
    def __init__(self) -> None:
        self._events: dict[str, list[dict[str, Any]]] = {}

    def append(self, *, session_id: str, event: dict[str, Any]) -> str:
        events = self._events.setdefault(session_id, [])
        reference = f"executor-evidence://sessions/{session_id}/events/{len(events)}"
        events.append({"evidence_ref": reference, **deepcopy(event)})
        return reference

    def session_events(self, *, session_id: str) -> list[dict[str, Any]]:
        return deepcopy(self._events.get(session_id, []))


class AuditStoreExecutorEvidenceSink:
    """Adapter for the existing GuardX audit/replay store."""

    def __init__(self, audit_store: Any) -> None:
        self._audit_store = audit_store

    def append(self, *, session_id: str, event: dict[str, Any]) -> str:
        execution_id = str(event.get("execution_id", "unknown"))
        reference = f"audit://sessions/{session_id}/executor/{execution_id}"
        self._audit_store.log(
            session_id=session_id,
            event_type="executor_integration_contract",
            risk_score=0.0,
            payload={"evidence_ref": reference, **event},
        )
        return reference

    def session_events(self, *, session_id: str) -> list[dict[str, Any]]:
        return [
            item["payload"]
            for item in self._audit_store.recent_by_session(session_id=session_id, limit=500)
            if item.get("event_type") == "executor_integration_contract"
        ]
