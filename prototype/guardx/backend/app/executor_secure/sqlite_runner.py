from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from app.executor_secure.models import PrecheckDecision
from app.executor_secure.permit import ExecutionPermit, PermitAuthority
from app.executor_secure.runner_base import PermitProtectedRunner
from app.executor_secure.sandbox import SandboxRun


_TABLE_RE = re.compile(r"\b(?:from|join|into|update)\s+([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
_FORBIDDEN_SQL = re.compile(
    r"\b(?:attach|detach|pragma|vacuum|create|alter|drop|replace|reindex|analyze|load_extension)\b",
    re.IGNORECASE,
)
_SCALAR_TYPES = (type(None), int, float, str, bytes)


def _json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"bytes_sha256": hashlib.sha256(value).hexdigest(), "length": len(value)}
    return value


class SandboxSqliteRunner(PermitProtectedRunner):
    runner_id = "sandbox_sqlite_runner"

    def __init__(self, sandbox: SandboxRun, authority: PermitAuthority, *, allowed_tables: set[str] | None = None) -> None:
        super().__init__(authority)
        self.sandbox = sandbox
        self.db_path = sandbox.sqlite_root / "sandbox.db"
        self.allowed_tables = {table.lower() for table in (allowed_tables or {"records"})}
        self._backups: dict[str, tuple[Path, str]] = {}
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
            conn.commit()

    def capability_precheck(self, capability: str, args: dict[str, Any]) -> bool:
        verb = str(args.get("sql", "")).lstrip().split(None, 1)[0].lower().rstrip(";")
        if verb == "select":
            return capability in {"sandbox.sqlite.read_write", "database_read", "database_write"}
        return capability in {"sandbox.sqlite.read_write", "database_write"}

    @staticmethod
    def _tables(sql: str) -> set[str]:
        return {match.lower() for match in _TABLE_RE.findall(sql)}

    def approval_target(self, args: dict[str, Any]) -> str:
        tables = sorted(self._tables(str(args.get("sql", ""))))
        return "sqlite/sandbox.db#" + ",".join(tables)

    def normalize_and_precheck(self, args: dict[str, Any]) -> PrecheckDecision:
        sql = str(args.get("sql", "")).strip()
        raw_params = args.get("params", [])
        params = list(raw_params) if isinstance(raw_params, (list, tuple)) else []
        allow_write = bool(args.get("allow_write", False))
        normalized = {"sql": sql, "params": params, "allow_write": allow_write, "transaction": True}
        lowered = sql.lower()
        if not sql or "--" in sql or "/*" in sql or sql.count(";") > (1 if sql.endswith(";") else 0):
            return PrecheckDecision(False, "comments or multiple SQL statements rejected", normalized)
        verb = lowered.split(None, 1)[0].rstrip(";")
        if verb not in {"select", "insert", "update", "delete"}:
            return PrecheckDecision(False, "SQL verb rejected", normalized)
        if _FORBIDDEN_SQL.search(sql):
            return PrecheckDecision(False, "forbidden SQL construct rejected", normalized)
        if any(not isinstance(value, _SCALAR_TYPES) for value in params):
            return PrecheckDecision(False, "non-scalar SQL parameter rejected", normalized)
        if verb != "select" and not allow_write:
            return PrecheckDecision(False, "write is not authorized", normalized)
        tables = self._tables(sql)
        if not tables or not tables.issubset(self.allowed_tables):
            return PrecheckDecision(False, "table is not allowlisted", normalized)
        return PrecheckDecision(True, "single-statement SQL transaction allowlisted", normalized)

    def _state(self, conn: sqlite3.Connection | None = None) -> dict[str, Any]:
        owns_connection = conn is None
        active = conn or sqlite3.connect(self.db_path)
        try:
            tables: dict[str, Any] = {}
            for table in sorted(self.allowed_tables):
                columns = [row[1] for row in active.execute(f'PRAGMA table_info("{table}")').fetchall()]
                rows = [list(map(_json_value, row)) for row in active.execute(f'SELECT * FROM "{table}"').fetchall()]
                rows.sort(key=lambda row: json.dumps(row, ensure_ascii=False, sort_keys=True))
                tables[table] = {"columns": columns, "rows": rows, "row_count": len(rows)}
            raw = json.dumps(tables, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            return {"sha256": hashlib.sha256(raw).hexdigest(), "tables": tables}
        finally:
            if owns_connection:
                active.close()

    def _create_backup(self, execution_id: str, before_hash: str) -> None:
        name = hashlib.sha256(execution_id.encode("utf-8")).hexdigest()[:24] + ".sqlite3"
        backup_path = self.sandbox.root / "snapshots" / name
        with closing(sqlite3.connect(self.db_path)) as source, closing(sqlite3.connect(backup_path)) as destination:
            source.backup(destination)
        self._backups[execution_id] = (backup_path, before_hash)

    def _authorizer(self, action: int, arg1: str | None, _arg2: str | None, _db: str | None, _trigger: str | None) -> int:
        table_actions = {sqlite3.SQLITE_READ, sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE}
        if action in table_actions and (arg1 or "").lower() not in self.allowed_tables:
            return sqlite3.SQLITE_DENY
        denied_actions = {
            sqlite3.SQLITE_ATTACH,
            sqlite3.SQLITE_DETACH,
            sqlite3.SQLITE_PRAGMA,
            sqlite3.SQLITE_CREATE_INDEX,
            sqlite3.SQLITE_CREATE_TABLE,
            sqlite3.SQLITE_CREATE_TEMP_INDEX,
            sqlite3.SQLITE_CREATE_TEMP_TABLE,
            sqlite3.SQLITE_CREATE_TEMP_TRIGGER,
            sqlite3.SQLITE_CREATE_TEMP_VIEW,
            sqlite3.SQLITE_CREATE_TRIGGER,
            sqlite3.SQLITE_CREATE_VIEW,
            sqlite3.SQLITE_DROP_INDEX,
            sqlite3.SQLITE_DROP_TABLE,
            sqlite3.SQLITE_DROP_TEMP_INDEX,
            sqlite3.SQLITE_DROP_TEMP_TABLE,
            sqlite3.SQLITE_DROP_TEMP_TRIGGER,
            sqlite3.SQLITE_DROP_TEMP_VIEW,
            sqlite3.SQLITE_DROP_TRIGGER,
            sqlite3.SQLITE_DROP_VIEW,
            sqlite3.SQLITE_ALTER_TABLE,
            sqlite3.SQLITE_REINDEX,
            sqlite3.SQLITE_ANALYZE,
        }
        return sqlite3.SQLITE_DENY if action in denied_actions else sqlite3.SQLITE_OK

    def run(self, *, execution_id: str, capability: str, args: dict[str, Any], permit: ExecutionPermit) -> dict[str, Any]:
        if execution_id != self.sandbox.execution_id:
            raise PermissionError("execution_id is not bound to this disposable sandbox")
        permit_hash = self._consume(permit, execution_id=execution_id, capability=capability, args=args)
        sql = str(args["sql"])
        params = list(args.get("params", []))
        verb = sql.lstrip().split(None, 1)[0].lower().rstrip(";")
        is_write = verb != "select"
        pre_state = self._state()
        if is_write:
            self._create_backup(execution_id, pre_state["sha256"])
        rows: list[tuple[Any, ...]] = []
        changed_rows = 0
        in_transaction_state = pre_state
        with closing(sqlite3.connect(self.db_path, isolation_level=None)) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE" if is_write else "BEGIN")
                conn.set_authorizer(self._authorizer)
                cursor = conn.execute(sql, params)
                if is_write:
                    changed_rows = cursor.rowcount
                    conn.set_authorizer(None)
                    in_transaction_state = self._state(conn)
                    conn.commit()
                else:
                    rows = cursor.fetchall()
                    conn.set_authorizer(None)
                    conn.rollback()
            except Exception:
                conn.set_authorizer(None)
                conn.rollback()
                if self._state()["sha256"] != pre_state["sha256"]:
                    raise RuntimeError("SQLite transaction rollback state mismatch")
                raise
        post_state = self._state()
        if is_write and post_state["sha256"] != in_transaction_state["sha256"]:
            raise RuntimeError("SQLite post-commit state verification mismatch")
        if not is_write and post_state["sha256"] != pre_state["sha256"]:
            raise RuntimeError("SQLite SELECT changed database state")
        return {
            "row_count": len(rows),
            "rows": [list(map(_json_value, row)) for row in rows],
            "changed_rows": changed_rows,
            "transaction": "committed" if is_write else "read_only_rolled_back",
            "pre_state": pre_state,
            "post_state": post_state,
            "state_verified": True,
            "permit_hash": permit_hash,
        }

    def rollback(self, execution_id: str) -> dict[str, Any]:
        entry = self._backups.pop(execution_id, None)
        if entry is None:
            return {"rollback_performed": False, "restored": False, "failure_reason": "no reversible transaction"}
        backup_path, expected_hash = entry
        before_rollback = self._state()["sha256"]
        with closing(sqlite3.connect(backup_path)) as source, closing(sqlite3.connect(self.db_path)) as destination:
            source.backup(destination)
        after_state = self._state()
        restored = after_state["sha256"] == expected_hash
        return {
            "rollback_performed": True,
            "restored": restored,
            "failure_reason": None if restored else "database state mismatch",
            "before_rollback_sha256": before_rollback,
            "after_rollback_sha256": after_state["sha256"],
            "expected_sha256": expected_hash,
        }

    def state_hash(self) -> str:
        return self._state()["sha256"]
