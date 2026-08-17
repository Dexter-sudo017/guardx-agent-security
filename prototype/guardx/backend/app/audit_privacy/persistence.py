from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from app.audit_privacy.sanitizer import PersistenceSanitizer


class PersistenceBoundary:
    def __init__(self, sanitizer: PersistenceSanitizer) -> None:
        self.sanitizer = sanitizer
        self.redaction_count = 0

    def sanitize(self, payload: Any) -> Any:
        sanitized, redactions = self.sanitizer.sanitize_with_report(payload)
        self.redaction_count += len(redactions)
        return sanitized

    def write_json(self, path: str | Path, payload: Any) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.sanitize(payload), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def write_jsonl(self, path: str | Path, rows: list[Any]) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(json.dumps(self.sanitize(row), ensure_ascii=False, sort_keys=True) for row in rows) + "\n", encoding="utf-8")

    def write_log(self, path: str | Path, message: Any) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        sanitized = self.sanitize(message)
        target.write_text(sanitized if isinstance(sanitized, str) else json.dumps(sanitized, ensure_ascii=False), encoding="utf-8")

    def write_audit_db(self, path: str | Path, rows: list[dict[str, Any]]) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(target)) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
            conn.executemany("INSERT INTO audit_events(payload) VALUES (?)", [(json.dumps(self.sanitize(row), ensure_ascii=False),) for row in rows])
            conn.commit()
