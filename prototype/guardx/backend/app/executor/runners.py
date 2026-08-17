from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any

from app.executor.runtime_models import ToolExecutionOutcome


class SimulatedSafeToolRunner:
    def run(self, *, execution_key: str, tool_name: str, args: dict[str, Any]) -> ToolExecutionOutcome:
        return ToolExecutionOutcome(
            output_ref=f"{execution_key}:simulated_execution",
            observation="GuardX allowed this action.",
            metadata={
                "tool_name": tool_name,
                "sanitized_arg_keys": sorted(args.keys()),
                "execution_mode": "simulated_safe_tool",
            },
        )

    def rollback(self, *, execution_key: str, tool_name: str, args: dict[str, Any], error: str) -> ToolExecutionOutcome:
        return ToolExecutionOutcome(
            output_ref=f"{execution_key}:rollback",
            observation="Rollback completed for failed executor stage.",
            metadata={"tool_name": tool_name, "error": error, "execution_mode": "simulated_safe_tool"},
        )


class LocalReadOnlySandboxRunner:
    """Read one text file from the fixed demo sandbox after Action Guard approval."""

    project_root = Path(__file__).resolve().parents[5]
    sandbox_root = (project_root / "sandbox" / "demo").resolve()
    max_bytes = 64 * 1024

    def run(self, *, execution_key: str, tool_name: str, args: dict[str, Any]) -> ToolExecutionOutcome:
        if tool_name != "read_file_safe":
            raise ValueError("local_readonly_sandbox only supports read_file_safe")

        requested = str(args.get("path") or "").strip()
        if not requested:
            raise ValueError("sandbox path is required")
        candidate = (self.project_root / requested).resolve()
        if not candidate.is_relative_to(self.sandbox_root):
            raise PermissionError("path is outside the GuardX demo sandbox")
        if not candidate.is_file():
            raise FileNotFoundError("sandbox file does not exist")
        if candidate.stat().st_size > self.max_bytes:
            raise ValueError("sandbox file exceeds the 64 KiB read limit")

        raw = candidate.read_bytes()
        content = raw.decode("utf-8")
        return ToolExecutionOutcome(
            output_ref=f"{execution_key}:sandbox_read",
            observation=content,
            metadata={
                "tool_name": tool_name,
                "execution_mode": "local_readonly_sandbox",
                "sandbox_path": candidate.relative_to(self.project_root).as_posix(),
                "bytes_read": len(raw),
                "content_sha256": sha256(raw).hexdigest(),
                "read_only": True,
            },
        )

    def rollback(self, *, execution_key: str, tool_name: str, args: dict[str, Any], error: str) -> ToolExecutionOutcome:
        return ToolExecutionOutcome(
            output_ref=f"{execution_key}:rollback_not_required",
            observation="Read-only sandbox access has no rollback action.",
            metadata={"tool_name": tool_name, "error": error, "execution_mode": "local_readonly_sandbox"},
        )
