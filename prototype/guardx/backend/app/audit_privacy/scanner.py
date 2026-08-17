from __future__ import annotations

import hashlib
import re
import zipfile
from pathlib import Path
from typing import Iterable


_TOKEN = re.compile(rb"GX(?:API|TOKEN|PASS|ENV|PII|NOTE)_[A-Za-z0-9_-]+")


def _matches(data: bytes, fingerprints: set[str]) -> list[str]:
    return [hashlib.sha256(match.group(0)).hexdigest() for match in _TOKEN.finditer(data) if hashlib.sha256(match.group(0)).hexdigest() in fingerprints]


def scan_persistent_paths(paths: Iterable[str | Path], fingerprints: set[str]) -> dict[str, object]:
    hits: list[dict[str, object]] = []
    scanned = 0
    for supplied in paths:
        path = Path(supplied)
        files = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()]
        for file_path in files:
            scanned += 1
            if file_path.suffix.lower() == ".zip":
                with zipfile.ZipFile(file_path) as archive:
                    for name in archive.namelist():
                        if name.endswith("/"):
                            continue
                        found = _matches(archive.read(name), fingerprints)
                        if found:
                            hits.append({"path": str(file_path), "archive_entry": name, "fingerprints": found})
            else:
                found = _matches(file_path.read_bytes(), fingerprints)
                if found:
                    hits.append({"path": str(file_path), "fingerprints": found})
    return {"scanned_file_count": scanned, "raw_canary_persistent_hit_count": sum(len(item["fingerprints"]) for item in hits), "hits": hits}
