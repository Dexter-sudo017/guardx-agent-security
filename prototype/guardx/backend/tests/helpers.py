from typing import Any

from fastapi.testclient import TestClient


def latest_audit_payload(client: TestClient, session_id: str, event_type: str | None = None) -> dict[str, Any]:
    audit = client.get(f"/v1/audit/sessions/{session_id}")
    assert audit.status_code == 200
    events = audit.json()["events"]
    if event_type is not None:
        events = [item for item in events if item["event_type"] == event_type]
    assert events
    return events[0]["payload"]
