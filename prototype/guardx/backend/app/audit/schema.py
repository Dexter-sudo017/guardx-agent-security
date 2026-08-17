import sqlite3


def init_audit_schema(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          created_at TEXT NOT NULL,
          session_id TEXT NOT NULL,
          event_type TEXT NOT NULL,
          risk_score REAL NOT NULL,
          payload TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_trace_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          audit_log_id INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          session_id TEXT NOT NULL,
          event_type TEXT NOT NULL,
          risk_score REAL NOT NULL,
          trace_id TEXT NOT NULL,
          span_id TEXT,
          stage TEXT,
          payload_ref TEXT,
          trace_event TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_decision_records (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          audit_log_id INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          session_id TEXT NOT NULL,
          event_type TEXT NOT NULL,
          risk_score REAL NOT NULL,
          request_id TEXT NOT NULL,
          trace_id TEXT NOT NULL,
          stage TEXT,
          surface TEXT,
          decision_record TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_trace_session_trace ON audit_trace_events (session_id, trace_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_trace_trace ON audit_trace_events (trace_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_decision_session_request ON audit_decision_records (session_id, request_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_decision_trace ON audit_decision_records (trace_id)")
