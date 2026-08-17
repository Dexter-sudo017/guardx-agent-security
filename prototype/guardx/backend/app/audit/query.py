import json
import sqlite3
from typing import Any


def recent_by_session_from_sql(conn: sqlite3.Connection, *, session_id: str, limit: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT created_at, event_type, risk_score, payload
        FROM audit_logs
        WHERE session_id = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (session_id, int(limit)),
    ).fetchall()
    return [
        {
            "created_at": created_at,
            "event_type": event_type,
            "risk_score": risk_score,
            "payload": json.loads(payload),
        }
        for created_at, event_type, risk_score, payload in rows
    ]


def recent_from_sql(conn: sqlite3.Connection, *, limit: int, event_type: str | None = None) -> list[dict[str, Any]]:
    query = """
        SELECT created_at, session_id, event_type, risk_score, payload
        FROM audit_logs
    """
    params: list[Any] = []
    if event_type:
        query += " WHERE event_type = ?"
        params.append(event_type)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(query, params).fetchall()
    return [
        {
            "created_at": created_at,
            "session_id": session_id,
            "event_type": event_type,
            "risk_score": risk_score,
            "payload": json.loads(payload),
        }
        for created_at, session_id, event_type, risk_score, payload in rows
    ]


def trace_events_from_index(
    conn: sqlite3.Connection,
    *,
    session_id: str | None = None,
    trace_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    query = """
        SELECT created_at, session_id, event_type, risk_score, trace_event
        FROM audit_trace_events
    """
    where: list[str] = []
    params: list[Any] = []
    if session_id:
        where.append("session_id = ?")
        params.append(session_id)
    if trace_id:
        where.append("trace_id = ?")
        params.append(trace_id)
    if where:
        query += " WHERE " + " AND ".join(where)
    query += " ORDER BY audit_log_id DESC, id ASC LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(query, params).fetchall()
    return [
        {
            "created_at": created_at,
            "session_id": row_session_id,
            "event_type": event_type,
            "risk_score": risk_score,
            "trace_event": json.loads(trace_event),
        }
        for created_at, row_session_id, event_type, risk_score, trace_event in rows
    ]


def decision_records_from_index(
    conn: sqlite3.Connection,
    *,
    session_id: str | None = None,
    request_id: str | None = None,
    trace_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    query = """
        SELECT created_at, session_id, event_type, risk_score, decision_record
        FROM audit_decision_records
    """
    where: list[str] = []
    params: list[Any] = []
    if session_id:
        where.append("session_id = ?")
        params.append(session_id)
    if request_id:
        where.append("request_id = ?")
        params.append(request_id)
    if trace_id:
        where.append("trace_id = ?")
        params.append(trace_id)
    if where:
        query += " WHERE " + " AND ".join(where)
    query += " ORDER BY audit_log_id DESC, id DESC LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(query, params).fetchall()
    return [
        {
            "created_at": created_at,
            "session_id": row_session_id,
            "event_type": event_type,
            "risk_score": risk_score,
            "decision_record": json.loads(decision_record),
        }
        for created_at, row_session_id, event_type, risk_score, decision_record in rows
    ]


def trace_events_from_payloads(
    audit_events: list[dict[str, Any]],
    *,
    session_id: str | None = None,
    trace_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    traces: list[dict[str, Any]] = []
    for audit_event in audit_events:
        payload = audit_event.get("payload")
        if not isinstance(payload, dict):
            continue
        trace_items = payload.get("trace_events")
        if not isinstance(trace_items, list):
            continue
        for trace_event in trace_items:
            if not isinstance(trace_event, dict):
                continue
            if trace_id and str(trace_event.get("trace_id")) != trace_id:
                continue
            traces.append(
                {
                    "created_at": audit_event.get("created_at"),
                    "session_id": audit_event.get("session_id", session_id),
                    "event_type": audit_event.get("event_type"),
                    "risk_score": audit_event.get("risk_score"),
                    "trace_event": trace_event,
                }
            )
            if len(traces) >= int(limit):
                return traces
    return traces


def decision_records_from_payloads(
    audit_events: list[dict[str, Any]],
    *,
    session_id: str | None = None,
    request_id: str | None = None,
    trace_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for audit_event in audit_events:
        payload = audit_event.get("payload")
        if not isinstance(payload, dict):
            continue
        decision_record = payload.get("decision_record")
        if not isinstance(decision_record, dict):
            continue
        if request_id and str(decision_record.get("request_id")) != request_id:
            continue
        if trace_id and str(decision_record.get("trace_id")) != trace_id:
            continue
        records.append(
            {
                "created_at": audit_event.get("created_at"),
                "session_id": audit_event.get("session_id", session_id),
                "event_type": audit_event.get("event_type"),
                "risk_score": audit_event.get("risk_score"),
                "decision_record": decision_record,
            }
        )
        if len(records) >= int(limit):
            return records
    return records
