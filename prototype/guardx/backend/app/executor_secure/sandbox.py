from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


class SandboxBoundaryError(ValueError):
    pass


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.exists():
        return digest.hexdigest()
    files: list[Path] = []
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        dirnames[:] = [name for name in dirnames if not _is_link_or_reparse(directory_path / name)]
        files.extend(
            path
            for name in filenames
            if (path := directory_path / name).is_file() and not _is_link_or_reparse(path)
        )
    for path in sorted(files, key=lambda p: p.as_posix()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _is_link_or_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = path.lstat().st_file_attributes
    except (AttributeError, FileNotFoundError, OSError):
        return False
    return bool(attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


@dataclass
class SandboxRun:
    execution_id: str
    base_root: Path
    root: Path
    created_at: str
    initial_state_hash: str

    @classmethod
    def create(cls, base_root: str | Path | None = None, execution_id: str | None = None) -> "SandboxRun":
        base = Path(base_root or tempfile.mkdtemp(prefix="guardx_sandbox_base_")).resolve()
        base.mkdir(parents=True, exist_ok=True)
        eid = execution_id or f"gxexec-{uuid4().hex}"
        if not eid.startswith("gxexec-") or not all(c.isalnum() or c in "-_" for c in eid):
            raise SandboxBoundaryError("invalid execution_id")
        root = (base / eid).resolve()
        if root.exists():
            raise SandboxBoundaryError("execution sandbox already exists")
        root.mkdir()
        for name in ("workspace", "sqlite", "network", "snapshots", "evidence", "logs"):
            (root / name).mkdir()
        created = datetime.now(timezone.utc).isoformat()
        return cls(eid, base, root, created, _tree_hash(root))

    @classmethod
    def open_existing(cls, base_root: str | Path, execution_id: str) -> "SandboxRun":
        base = Path(base_root).resolve()
        if not execution_id.startswith("gxexec-") or not all(c.isalnum() or c in "-_" for c in execution_id):
            raise SandboxBoundaryError("invalid execution_id")
        root = (base / execution_id).resolve()
        if root.parent != base or not root.is_dir():
            raise SandboxBoundaryError("execution sandbox does not exist inside base root")
        required = {"workspace", "sqlite", "network", "snapshots", "evidence", "logs"}
        if not all((root / name).is_dir() for name in required):
            raise SandboxBoundaryError("execution sandbox layout is incomplete")
        return cls(execution_id, base, root, "unknown", _tree_hash(root))

    @property
    def workspace(self) -> Path:
        return self.root / "workspace"

    @property
    def sqlite_root(self) -> Path:
        return self.root / "sqlite"

    def resolve_workspace_path(self, supplied: str) -> Path:
        normalized = unicodedata.normalize("NFKC", str(supplied).strip()).replace("/", os.sep).replace("\\", os.sep)
        supplied_path = Path(normalized)
        if not normalized or "\x00" in normalized or supplied_path.is_absolute() or supplied_path.drive:
            raise SandboxBoundaryError("absolute or empty path rejected")
        if any(part in {"", ".."} for part in supplied_path.parts):
            raise SandboxBoundaryError("path traversal component rejected")
        if any(":" in part for part in supplied_path.parts):
            raise SandboxBoundaryError("alternate stream or drive syntax rejected")
        workspace = self.workspace.resolve(strict=True)
        current = workspace
        for part in supplied_path.parts:
            current = current / part
            if current.exists() and _is_link_or_reparse(current):
                raise SandboxBoundaryError("symlink or reparse-point path rejected")
        candidate = (workspace / supplied_path).resolve(strict=False)
        try:
            common = Path(os.path.commonpath([os.path.normcase(str(candidate)), os.path.normcase(str(workspace))]))
        except ValueError as exc:
            raise SandboxBoundaryError("path boundary mismatch") from exc
        if os.path.normcase(str(common)) != os.path.normcase(str(workspace)):
            raise SandboxBoundaryError("path escapes sandbox workspace")
        return candidate

    def canonical_workspace_target(self, supplied: str) -> str:
        target = self.resolve_workspace_path(supplied)
        return "workspace/" + target.relative_to(self.workspace.resolve()).as_posix()

    def workspace_hash(self) -> str:
        return _tree_hash(self.workspace)

    def sqlite_hash(self) -> str:
        return _tree_hash(self.sqlite_root)

    def state_hash(self) -> str:
        return self.workspace_hash() + ":" + self.sqlite_hash()

    def cleanup(self) -> None:
        resolved = self.root.resolve()
        if resolved.parent != self.base_root.resolve() or not resolved.name.startswith("gxexec-"):
            raise SandboxBoundaryError("refusing unsafe sandbox cleanup")
        shutil.rmtree(resolved)
