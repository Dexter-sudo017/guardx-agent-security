import json
import sqlite3
from typing import Any


def index_payload(conn: sqlite3.Connection, audit_log_id: int, item: dict[str, Any]) -> dict[str, int]:
    indexed = {"trace_events": 0, "decision_records": 0}
    payload = item.get("payload")
    if not isinstance(payload, dict):
        return indexed
    trace_items = payload.get("trace_events")
    if isinstance(trace_items, list):
        for trace_event in trace_items:
            if not isinstance(trace_event, dict):
                continue
            conn.execute(
                """
                INSERT INTO audit_trace_events (
                  audit_log_id, created_at, session_id, event_type, risk_score,
                  trace_id, span_id, stage, payload_ref, trace_event
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_log_id,
                    item["created_at"],
                    item["session_id"],
                    item["event_type"],
                    item["risk_score"],
                    str(trace_event.get("trace_id") or ""),
                    str(trace_event.get("span_id") or ""),
                    str(trace_event.get("stage") or ""),
                    str(trace_event.get("payload_ref") or ""),
                    json.dumps(trace_event, ensure_ascii=False),
                ),
            )
            indexed["trace_events"] += 1
    decision_record = payload.get("decision_record")
    if isinstance(decision_record, dict):
        conn.execute(
            """
            INSERT INTO audit_decision_records (
              audit_log_id, created_at, session_id, event_type, risk_score,
              request_id, trace_id, stage, surface, decision_record
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_log_id,
                item["created_at"],
                item["session_id"],
                item["event_type"],
                item["risk_score"],
                str(decision_record.get("request_id") or ""),
                str(decision_record.get("trace_id") or ""),
                str(decision_record.get("stage") or ""),
                str(decision_record.get("surface") or ""),
                json.dumps(decision_record, ensure_ascii=False),
            ),
        )
        indexed["decision_records"] += 1
    return indexed


def rebuild_audit_indexes(conn: sqlite3.Connection, *, session_id: str | None = None, limit: int | None = None) -> dict[str, Any]:
    query = """
        SELECT id, created_at, session_id, event_type, risk_score, payload
        FROM audit_logs
    """
    params: list[Any] = []
    if session_id:
        query += " WHERE session_id = ?"
        params.append(session_id)
    query += " ORDER BY id DESC"
    if limit is not None:
        query += " LIMIT ?"
        params.append(int(limit))
    summary = {"sqlite_enabled": True, "audit_logs_scanned": 0, "trace_events": 0, "decision_records": 0}
    rows = conn.execute(query, params).fetchall()
    for audit_log_id, created_at, row_session_id, event_type, risk_score, payload in rows:
        conn.execute("DELETE FROM audit_trace_events WHERE audit_log_id = ?", (audit_log_id,))
        conn.execute("DELETE FROM audit_decision_records WHERE audit_log_id = ?", (audit_log_id,))
        indexed = index_payload(
            conn,
            int(audit_log_id),
            {
                "created_at": created_at,
                "session_id": row_session_id,
                "event_type": event_type,
                "risk_score": risk_score,
                "payload": json.loads(payload),
            },
        )
        summary["audit_logs_scanned"] += 1
        summary["trace_events"] += indexed["trace_events"]
        summary["decision_records"] += indexed["decision_records"]
    return summary
