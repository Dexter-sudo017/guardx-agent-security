from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import asdict, dataclass
from typing import Any


class PermitError(PermissionError):
    pass


def normalized_args_hash(args: dict[str, Any]) -> str:
    raw = json.dumps(args, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ExecutionPermit:
    execution_id: str
    runner_id: str
    capability: str
    normalized_args_hash: str
    expires_at: float
    nonce: str
    signature: str

    def public_hash(self) -> str:
        raw = json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


class PermitAuthority:
    def __init__(self, secret: bytes | None = None) -> None:
        self._secret = secret or secrets.token_bytes(32)
        self._used: set[str] = set()

    def _signature(self, fields: tuple[str, ...]) -> str:
        return hmac.new(self._secret, "\x1f".join(fields).encode("utf-8"), hashlib.sha256).hexdigest()

    def issue(self, *, execution_id: str, runner_id: str, capability: str, args: dict[str, Any], ttl_seconds: float = 30.0) -> ExecutionPermit:
        expires = time.time() + ttl_seconds
        nonce = secrets.token_hex(16)
        args_hash = normalized_args_hash(args)
        fields = (execution_id, runner_id, capability, args_hash, f"{expires:.6f}", nonce)
        return ExecutionPermit(execution_id, runner_id, capability, args_hash, expires, nonce, self._signature(fields))

    def validate_and_consume(self, permit: ExecutionPermit, *, execution_id: str, runner_id: str, capability: str, args: dict[str, Any]) -> str:
        if not isinstance(permit, ExecutionPermit):
            raise PermitError("missing execution permit")
        fields = (permit.execution_id, permit.runner_id, permit.capability, permit.normalized_args_hash, f"{permit.expires_at:.6f}", permit.nonce)
        if not hmac.compare_digest(permit.signature, self._signature(fields)):
            raise PermitError("invalid permit signature")
        if permit.expires_at < time.time():
            raise PermitError("expired permit")
        expected = (execution_id, runner_id, capability, normalized_args_hash(args))
        observed = (permit.execution_id, permit.runner_id, permit.capability, permit.normalized_args_hash)
        if observed != expected:
            raise PermitError("permit binding mismatch")
        if permit.nonce in self._used:
            raise PermitError("permit replay rejected")
        self._used.add(permit.nonce)
        return permit.public_hash()
