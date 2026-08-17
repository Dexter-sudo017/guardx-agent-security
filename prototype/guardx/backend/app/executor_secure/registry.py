from __future__ import annotations

from dataclasses import dataclass

from app.executor_secure.file_runner import SandboxFileRunner
from app.executor_secure.network_runner import LocalHttpRunner
from app.executor_secure.permit import PermitAuthority
from app.executor_secure.runner_base import SecureRunner
from app.executor_secure.sandbox import SandboxRun
from app.executor_secure.sqlite_runner import SandboxSqliteRunner


@dataclass(frozen=True)
class RunnerDescriptor:
    runner_id: str
    real_execution: bool
    dry_run: bool
    rollback_supported: bool


class SecureRunnerRegistry:
    def __init__(self, sandbox: SandboxRun, authority: PermitAuthority, *, http_host: str = "127.0.0.1", http_port: int | None = None, http_paths: set[str] | None = None) -> None:
        self.runners: dict[str, SecureRunner] = {
            "sandbox_file_runner": SandboxFileRunner(sandbox, authority),
            "sandbox_sqlite_runner": SandboxSqliteRunner(sandbox, authority),
        }
        if http_port is not None:
            self.runners["local_http_runner"] = LocalHttpRunner(
                sandbox,
                authority,
                allowed_host=http_host,
                allowed_port=http_port,
                allowed_paths=http_paths or {"/ok", "/echo"},
                event_log_path=sandbox.root / "network" / "executor_events.jsonl",
            )

    def get(self, runner_id: str) -> SecureRunner:
        try:
            return self.runners[runner_id]
        except KeyError as exc:
            raise KeyError(f"unregistered secure runner: {runner_id}") from exc

    def inventory(self) -> list[RunnerDescriptor]:
        return [
            RunnerDescriptor("sandbox_file_runner", True, False, True),
            RunnerDescriptor("local_http_runner", True, False, False),
            RunnerDescriptor("sandbox_sqlite_runner", True, False, True),
        ]
