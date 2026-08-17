import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.audit.indexer import index_payload, rebuild_audit_indexes
from app.audit.query import (
    decision_records_from_index,
    decision_records_from_payloads,
    recent_by_session_from_sql,
    recent_from_sql,
    trace_events_from_index,
    trace_events_from_payloads,
)
from app.audit.schema import init_audit_schema
from app.audit_privacy.sanitizer import sanitize_persistent_payload
from app.config import SETTINGS


PROJECT_ROOT = Path(__file__).resolve().parents[5]


class AuditStore:
    def __init__(self, sqlite_path: str = SETTINGS.sqlite_path) -> None:
        configured = Path(sqlite_path)
        self._path = configured if configured.is_absolute() else PROJECT_ROOT / configured
        self._memory_logs: list[dict[str, Any]] = []
        self._sqlite_enabled = True
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(self._path)

    def _init_db(self) -> None:
        try:
            with self._connect() as conn:
                init_audit_schema(conn)
                conn.commit()
        except sqlite3.Error:
            self._sqlite_enabled = False

    def log(self, session_id: str, event_type: str, risk_score: float, payload: dict[str, Any]) -> None:
        payload = sanitize_persistent_payload(payload)
        item = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "event_type": event_type,
            "risk_score": float(risk_score),
            "payload": payload,
        }
        with self._lock:
            if not self._sqlite_enabled:
                self._memory_logs.append(item)
                return
            try:
                with self._connect() as conn:
                    cursor = conn.execute(
                        """
                        INSERT INTO audit_logs (created_at, session_id, event_type, risk_score, payload)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            item["created_at"],
                            item["session_id"],
                            item["event_type"],
                            item["risk_score"],
                            json.dumps(payload, ensure_ascii=False),
                        ),
                    )
                    index_payload(conn, int(cursor.lastrowid), item)
                    conn.commit()
            except sqlite3.Error:
                self._sqlite_enabled = False
                self._memory_logs.append(item)

    def rebuild_indexes(self, *, session_id: str | None = None, limit: int | None = None) -> dict[str, Any]:
        if not self._sqlite_enabled:
            return {"sqlite_enabled": False, "audit_logs_scanned": 0, "trace_events": 0, "decision_records": 0}
        try:
            with self._connect() as conn:
                summary = rebuild_audit_indexes(conn, session_id=session_id, limit=limit)
                conn.commit()
                return summary
        except (sqlite3.Error, ValueError):
            self._sqlite_enabled = False
            return {"sqlite_enabled": False, "audit_logs_scanned": 0, "trace_events": 0, "decision_records": 0}

    def recent_by_session(self, session_id: str, limit: int = 50) -> list[dict[str, Any]]:
        if not self._sqlite_enabled:
            return [
                {
                    "created_at": item["created_at"],
                    "event_type": item["event_type"],
                    "risk_score": item["risk_score"],
                    "payload": item["payload"],
                }
                for item in reversed(self._memory_logs)
                if item["session_id"] == session_id
            ][:limit]
        try:
            with self._connect() as conn:
                return recent_by_session_from_sql(conn, session_id=session_id, limit=limit)
        except sqlite3.Error:
            self._sqlite_enabled = False
            return self.recent_by_session(session_id=session_id, limit=limit)

    def recent(self, limit: int = 200, event_type: str | None = None) -> list[dict[str, Any]]:
        if not self._sqlite_enabled:
            items = list(reversed(self._memory_logs))
            if event_type:
                items = [item for item in items if item["event_type"] == event_type]
            return items[:limit]
        try:
            with self._connect() as conn:
                return recent_from_sql(conn, limit=limit, event_type=event_type)
        except sqlite3.Error:
            self._sqlite_enabled = False
            return self.recent(limit=limit, event_type=event_type)

    def _audit_events_for_fallback(self, *, session_id: str | None, limit: int) -> list[dict[str, Any]]:
        scan_limit = max(int(limit), min(1000, int(limit) * 5))
        return self.recent_by_session(session_id=session_id, limit=scan_limit) if session_id else self.recent(limit=scan_limit)

    def trace_events(
        self,
        *,
        session_id: str | None = None,
        trace_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if self._sqlite_enabled:
            try:
                with self._connect() as conn:
                    indexed = trace_events_from_index(conn, session_id=session_id, trace_id=trace_id, limit=limit)
                if indexed:
                    return indexed
            except sqlite3.Error:
                self._sqlite_enabled = False
        return trace_events_from_payloads(
            self._audit_events_for_fallback(session_id=session_id, limit=limit),
            session_id=session_id,
            trace_id=trace_id,
            limit=limit,
        )

    def decision_records(
        self,
        *,
        session_id: str | None = None,
        request_id: str | None = None,
        trace_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if self._sqlite_enabled:
            try:
                with self._connect() as conn:
                    indexed = decision_records_from_index(
                        conn,
                        session_id=session_id,
                        request_id=request_id,
                        trace_id=trace_id,
                        limit=limit,
                    )
                if indexed:
                    return indexed
            except sqlite3.Error:
                self._sqlite_enabled = False
        return decision_records_from_payloads(
            self._audit_events_for_fallback(session_id=session_id, limit=limit),
            session_id=session_id,
            request_id=request_id,
            trace_id=trace_id,
            limit=limit,
        )
