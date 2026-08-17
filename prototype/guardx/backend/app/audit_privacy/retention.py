from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RetentionPolicy:
    audit_retention_days: int
    evidence_retention_days: int
    transient_sandbox_ttl_hours: int


def purge_audit_rows(db_path: str | Path, *, cutoff: datetime, dry_run: bool) -> dict[str, Any]:
    with closing(sqlite3.connect(Path(db_path))) as conn:
        count = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE created_at < ?", (cutoff.isoformat(),)).fetchone()[0]
        if not dry_run:
            conn.execute("DELETE FROM audit_logs WHERE created_at < ?", (cutoff.isoformat(),))
            conn.commit()
    return {"dry_run": dry_run, "eligible": count, "deleted": 0 if dry_run else count}


def purge_expired_directories(root: str | Path, *, ttl_hours: int, now: datetime | None = None, dry_run: bool = True) -> dict[str, Any]:
    active_now = now or datetime.now(timezone.utc)
    cutoff = active_now - timedelta(hours=ttl_hours)
    eligible: list[str] = []
    for path in Path(root).iterdir() if Path(root).exists() else []:
        if path.is_dir() and datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) < cutoff:
            eligible.append(path.name)
    if not dry_run:
        import shutil
        for name in eligible:
            target = (Path(root) / name).resolve()
            if target.parent != Path(root).resolve():
                raise ValueError("unsafe retention target")
            shutil.rmtree(target)
    return {"dry_run": dry_run, "eligible": eligible, "deleted": [] if dry_run else eligible}
