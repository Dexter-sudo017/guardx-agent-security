from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from app.executor_secure.models import PrecheckDecision
from app.executor_secure.permit import ExecutionPermit, PermitAuthority
from app.executor_secure.runner_base import PermitProtectedRunner
from app.executor_secure.sandbox import SandboxBoundaryError, SandboxRun


class SandboxFileRunner(PermitProtectedRunner):
    runner_id = "sandbox_file_runner"

    def __init__(self, sandbox: SandboxRun, authority: PermitAuthority) -> None:
        super().__init__(authority)
        self.sandbox = sandbox
        self.target_access_count = 0
        self._backups: dict[str, tuple[Path, bool, bytes]] = {}

    def capability_precheck(self, capability: str, args: dict[str, Any]) -> bool:
        operation = str(args.get("operation", ""))
        allowed = {
            "read": {"sandbox.file.read", "file_read"},
            "write": {"sandbox.file.write", "file_write"},
            "overwrite": {"sandbox.file.write", "file_write"},
            "delete": {"file_delete"},
        }
        return capability in allowed.get(operation, set())

    def approval_target(self, args: dict[str, Any]) -> str:
        return self.sandbox.canonical_workspace_target(str(args.get("path", "")))

    def normalize_and_precheck(self, args: dict[str, Any]) -> PrecheckDecision:
        operation = str(args.get("operation", "")).strip().lower()
        path = str(args.get("path", "")).strip()
        normalized = {"operation": operation, "path": path}
        if operation in {"write", "overwrite"}:
            normalized["content"] = str(args.get("content", ""))
        if operation not in {"read", "write", "overwrite", "delete"}:
            return PrecheckDecision(False, "unsupported file operation", normalized)
        if Path(path).name.lower() in {".env", "credentials", "credentials.json", "id_rsa"}:
            return PrecheckDecision(False, "sensitive file policy", normalized)
        try:
            self.sandbox.resolve_workspace_path(path)
        except SandboxBoundaryError as exc:
            return PrecheckDecision(False, str(exc), normalized)
        return PrecheckDecision(True, "workspace path allowed", normalized)

    def run(self, *, execution_id: str, capability: str, args: dict[str, Any], permit: ExecutionPermit) -> dict[str, Any]:
        if execution_id != self.sandbox.execution_id:
            raise PermissionError("execution_id is not bound to this disposable sandbox")
        permit_hash = self._consume(permit, execution_id=execution_id, capability=capability, args=args)
        target = self.sandbox.resolve_workspace_path(str(args["path"]))
        operation = str(args["operation"])
        self.target_access_count += 1
        before_exists = target.exists()
        before = target.read_bytes() if before_exists else b""
        if operation == "read":
            target = self.sandbox.resolve_workspace_path(str(args["path"]))
            if not before_exists or not target.is_file():
                raise FileNotFoundError(target.name)
            digest = hashlib.sha256(before).hexdigest()
            return {
                "content": before.decode("utf-8"),
                "sha256": digest,
                "pre_target_sha256": digest,
                "post_target_sha256": digest,
                "state_verified": target.read_bytes() == before,
                "permit_hash": permit_hash,
            }
        if operation == "delete":
            target = self.sandbox.resolve_workspace_path(str(args["path"]))
            if not before_exists or not target.is_file():
                raise FileNotFoundError(target.name)
            self._backups[execution_id] = (target, True, before)
            target.unlink()
            return {
                "deleted": True,
                "pre_target_sha256": hashlib.sha256(before).hexdigest(),
                "post_target_sha256": None,
                "state_verified": not target.exists(),
                "permit_hash": permit_hash,
            }
        if operation == "write" and before_exists:
            raise FileExistsError(target.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target = self.sandbox.resolve_workspace_path(str(args["path"]))
        self._backups[execution_id] = (target, before_exists, before)
        payload = str(args.get("content", "")).encode("utf-8")
        target.write_bytes(payload)
        post = target.read_bytes()
        return {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes_written": len(payload),
            "pre_target_sha256": hashlib.sha256(before).hexdigest() if before_exists else None,
            "post_target_sha256": hashlib.sha256(post).hexdigest(),
            "state_verified": post == payload,
            "permit_hash": permit_hash,
        }

    def rollback(self, execution_id: str) -> dict[str, Any]:
        if execution_id not in self._backups:
            return {"rollback_performed": False, "restored": False, "failure_reason": "no reversible file operation"}
        target, existed, content = self._backups.pop(execution_id)
        if existed:
            target.write_bytes(content)
        elif target.exists():
            target.unlink()
        restored = target.exists() == existed and (not existed or target.read_bytes() == content)
        return {"rollback_performed": True, "restored": restored, "failure_reason": None if restored else "state mismatch"}

    def state_hash(self) -> str:
        return self.sandbox.workspace_hash()
