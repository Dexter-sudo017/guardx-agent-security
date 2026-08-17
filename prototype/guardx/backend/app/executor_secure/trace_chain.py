from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


GENESIS_HASH = "0" * 64


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class TraceChain:
    def __init__(self, execution_id: str) -> None:
        self.execution_id = execution_id
        self.events: list[dict[str, Any]] = []

    def append(self, event_type: str, **fields: Any) -> dict[str, Any]:
        previous = self.events[-1]["event_hash"] if self.events else GENESIS_HASH
        event = {
            "execution_id": self.execution_id,
            "sequence_number": len(self.events) + 1,
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous_event_hash": previous,
            **fields,
        }
        event["event_hash"] = hashlib.sha256(_canonical(event)).hexdigest()
        self.events.append(event)
        return event

    @property
    def root_hash(self) -> str:
        return self.events[-1]["event_hash"] if self.events else GENESIS_HASH


def verify_trace(events: list[dict[str, Any]]) -> dict[str, Any]:
    failures: list[str] = []
    previous = GENESIS_HASH
    execution_id = events[0].get("execution_id") if events else None
    for index, original in enumerate(events, start=1):
        event = dict(original)
        observed_hash = str(event.pop("event_hash", ""))
        if event.get("execution_id") != execution_id:
            failures.append(f"event {index}: execution_id mismatch")
        if event.get("sequence_number") != index:
            failures.append(f"event {index}: sequence mismatch")
        if event.get("previous_event_hash") != previous:
            failures.append(f"event {index}: previous hash mismatch")
        expected_hash = hashlib.sha256(_canonical(event)).hexdigest()
        if observed_hash != expected_hash:
            failures.append(f"event {index}: event hash mismatch")
        previous = observed_hash
    return {
        "verified": bool(events) and not failures,
        "event_count": len(events),
        "trace_root_hash": previous if events else GENESIS_HASH,
        "failures": failures,
    }
