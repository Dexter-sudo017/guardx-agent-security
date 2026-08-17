from __future__ import annotations

from typing import Any, Protocol

from app.executor_secure.models import PrecheckDecision
from app.executor_secure.permit import ExecutionPermit, PermitAuthority


class SecureRunner(Protocol):
    runner_id: str
    invocation_count: int

    def normalize_and_precheck(self, args: dict[str, Any]) -> PrecheckDecision: ...
    def capability_precheck(self, capability: str, args: dict[str, Any]) -> bool: ...
    def approval_target(self, args: dict[str, Any]) -> str: ...
    def run(self, *, execution_id: str, capability: str, args: dict[str, Any], permit: ExecutionPermit) -> dict[str, Any]: ...
    def state_hash(self) -> str: ...
    def rollback(self, execution_id: str) -> dict[str, Any]: ...


class PermitProtectedRunner:
    runner_id = "secure_runner"

    def __init__(self, authority: PermitAuthority) -> None:
        self.authority = authority
        self.invocation_count = 0

    def capability_precheck(self, capability: str, args: dict[str, Any]) -> bool:
        return False

    def approval_target(self, args: dict[str, Any]) -> str:
        raise NotImplementedError

    def _consume(self, permit: ExecutionPermit, *, execution_id: str, capability: str, args: dict[str, Any]) -> str:
        permit_hash = self.authority.validate_and_consume(
            permit,
            execution_id=execution_id,
            runner_id=self.runner_id,
            capability=capability,
            args=args,
        )
        self.invocation_count += 1
        return permit_hash
