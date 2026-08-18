from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse


router = APIRouter()
FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "enterprise_rag"
MANIFEST_PATH = FIXTURE_ROOT / "manifest.json"


@lru_cache(maxsize=1)
def _manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _allowed_files() -> set[str]:
    return {
        str(case[label]["file"])
        for case in _manifest().get("pairs") or []
        for label in ("benign", "attack")
    }


@router.get("/v1/demo/enterprise-rag/manifest")
def enterprise_rag_manifest() -> dict:
    return _manifest()


@router.get("/v1/demo/enterprise-rag/files/{filename}")
def enterprise_rag_file(filename: str) -> FileResponse:
    safe_name = Path(filename).name
    if safe_name != filename or safe_name not in _allowed_files():
        raise HTTPException(status_code=404, detail="demo fixture not found")
    path = FIXTURE_ROOT / safe_name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="demo fixture not found")
    return FileResponse(path, filename=safe_name, media_type="application/octet-stream")
