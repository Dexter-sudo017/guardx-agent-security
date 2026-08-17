from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from app.executor_secure.permit import normalized_args_hash


ApprovalStatus = Literal[
    "RUNNING",
    "REQUIRE_APPROVAL",
    "PAUSED",
    "APPROVED",
    "REJECTED",
    "RESUMED",
    "TERMINATED",
]

TRUSTED_APPROVAL_ORIGINS = frozenset({"authenticated_user", "trusted_operator"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class ApprovalBinding:
    approval_id: str
    session_id: str
    capability: str
    tool: str
    target: str
    arguments_hash: str


@dataclass(frozen=True)
class ApprovalGrant:
    approval_id: str
    session_id: str
    capability: str
    tool: str
    target: str
    arguments_hash: str
    once: bool
    usage_limit: int
    expires_at: str
    created_at: str
    created_by: str
    trusted_origin: str
    nonce: str
    signature: str

    def signed_fields(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature")
        return value


class ApprovalSigner:
    """Trusted-control-plane signer; never pass this object to a model/provider."""

    def __init__(self, secret: bytes, *, trusted_origins: frozenset[str] = TRUSTED_APPROVAL_ORIGINS) -> None:
        if len(secret) < 32:
            raise ValueError("approval signing secret must be at least 32 bytes")
        self._secret = bytes(secret)
        self._trusted_origins = trusted_origins

    def issue(
        self,
        binding: ApprovalBinding,
        *,
        created_by: str,
        trusted_origin: str,
        ttl_seconds: float = 300.0,
        once: bool = True,
        usage_count: int = 1,
    ) -> ApprovalGrant:
        if trusted_origin not in self._trusted_origins:
            raise PermissionError("approval origin is not trusted")
        if not created_by.strip():
            raise ValueError("created_by is required")
        if ttl_seconds <= 0:
            raise ValueError("approval expiry must be in the future")
        if usage_count < 1 or (once and usage_count != 1):
            raise ValueError("once grants require usage_count=1")
        created_at = _now()
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
        fields = {
            **asdict(binding),
            "once": once,
            "usage_limit": usage_count,
            "expires_at": expires_at,
            "created_at": created_at,
            "created_by": created_by,
            "trusted_origin": trusted_origin,
            "nonce": secrets.token_hex(16),
        }
        signature = hmac.new(self._secret, _canonical(fields), hashlib.sha256).hexdigest()
        return ApprovalGrant(**fields, signature=signature)


@dataclass
class ApprovalRecord:
    approval_id: str
    execution_id: str
    session_id: str
    status: ApprovalStatus
    request: dict[str, Any]
    runner_id: str
    capability: str
    tool: str
    target: str
    args: dict[str, Any]
    arguments_hash: str
    once: bool | None
    usage_limit: int
    usage_count: int
    expires_at: str | None
    created_by: str | None
    trusted_origin: str | None
    grant: dict[str, Any] | None
    created_at: str
    updated_at: str
    events: list[dict[str, Any]] = field(default_factory=list)
    execution_result: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def binding(self) -> ApprovalBinding:
        return ApprovalBinding(
            approval_id=self.approval_id,
            session_id=self.session_id,
            capability=self.capability,
            tool=self.tool,
            target=self.target,
            arguments_hash=self.arguments_hash,
        )


class ApprovalStore:
    def __init__(
        self,
        path: Path,
        verification_secret: bytes,
        *,
        trusted_origins: frozenset[str] = TRUSTED_APPROVAL_ORIGINS,
    ) -> None:
        if len(verification_secret) < 32:
            raise ValueError("approval verification secret must be at least 32 bytes")
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._verification_secret = bytes(verification_secret)
        self._trusted_origins = trusted_origins
        self._lock = threading.RLock()

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("approval store must contain a JSON object")
        return raw

    def _save(self, records: dict[str, dict[str, Any]]) -> None:
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(records, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temp.replace(self.path)

    @staticmethod
    def _append_event(record: dict[str, Any], event_type: ApprovalStatus, payload: dict[str, Any] | None = None) -> None:
        events = record.setdefault("events", [])
        prev_hash = events[-1]["event_hash"] if events else "0" * 64
        body = {
            "sequence": len(events),
            "event_type": event_type,
            "timestamp": _now(),
            "payload": payload or {},
            "prev_hash": prev_hash,
        }
        body["event_hash"] = hashlib.sha256(_canonical(body)).hexdigest()
        events.append(body)

    def create(
        self,
        *,
        execution_id: str,
        session_id: str,
        request: dict[str, Any],
        runner_id: str,
        capability: str,
        tool: str,
        target: str,
        args: dict[str, Any],
    ) -> ApprovalRecord:
        if not session_id.strip() or not tool.strip() or not target.strip():
            raise ValueError("approval session_id, tool, and target are required")
        with self._lock:
            records = self._load()
            approval_id = "appr_" + secrets.token_hex(16)
            timestamp = _now()
            args_hash = normalized_args_hash(args)
            record = ApprovalRecord(
                approval_id=approval_id,
                execution_id=execution_id,
                session_id=session_id,
                status="RUNNING",
                request=request,
                runner_id=runner_id,
                capability=capability,
                tool=tool,
                target=target,
                args=args,
                arguments_hash=args_hash,
                once=None,
                usage_limit=0,
                usage_count=0,
                expires_at=None,
                created_by=None,
                trusted_origin=None,
                grant=None,
                created_at=timestamp,
                updated_at=timestamp,
            ).as_dict()
            binding_payload = {
                "session_id": session_id,
                "runner_id": runner_id,
                "capability": capability,
                "tool": tool,
                "target": target,
                "request_sha256": hashlib.sha256(_canonical(request)).hexdigest(),
                "arguments_hash": args_hash,
            }
            self._append_event(record, "RUNNING", binding_payload)
            self._append_event(record, "REQUIRE_APPROVAL", binding_payload)
            record["status"] = "PAUSED"
            record["updated_at"] = _now()
            self._append_event(record, "PAUSED", {"side_effect_permitted": False})
            records[approval_id] = record
            self._save(records)
            return ApprovalRecord(**record)

    def get(self, approval_id: str) -> ApprovalRecord:
        with self._lock:
            try:
                return ApprovalRecord(**self._load()[approval_id])
            except KeyError as exc:
                raise KeyError(f"unknown approval id: {approval_id}") from exc

    def _verify_grant_signature(self, grant: ApprovalGrant) -> bool:
        expected = hmac.new(self._verification_secret, _canonical(grant.signed_fields()), hashlib.sha256).hexdigest()
        return hmac.compare_digest(grant.signature, expected)

    def approve(self, approval_id: str, grant: ApprovalGrant) -> ApprovalRecord:
        with self._lock:
            records = self._load()
            if approval_id not in records:
                raise KeyError(f"unknown approval id: {approval_id}")
            record = records[approval_id]
            if record["status"] != "PAUSED":
                raise ValueError(f"invalid approval transition: {record['status']} -> APPROVED")
            if grant.trusted_origin not in self._trusted_origins or not self._verify_grant_signature(grant):
                raise PermissionError("approval grant does not have a trusted signature/origin")
            expected = ApprovalRecord(**record).binding()
            observed = ApprovalBinding(
                grant.approval_id,
                grant.session_id,
                grant.capability,
                grant.tool,
                grant.target,
                grant.arguments_hash,
            )
            if observed != expected:
                raise PermissionError("approval grant binding mismatch")
            if datetime.fromisoformat(grant.expires_at) <= datetime.now(timezone.utc):
                raise PermissionError("approval grant is expired")
            record.update(
                {
                    "status": "APPROVED",
                    "updated_at": _now(),
                    "once": grant.once,
                    "usage_limit": grant.usage_limit,
                    "expires_at": grant.expires_at,
                    "created_by": grant.created_by,
                    "trusted_origin": grant.trusted_origin,
                    "grant": asdict(grant),
                }
            )
            self._append_event(
                record,
                "APPROVED",
                {
                    "created_by": grant.created_by,
                    "trusted_origin": grant.trusted_origin,
                    "once": grant.once,
                    "usage_limit": grant.usage_limit,
                    "expires_at": grant.expires_at,
                    "grant_sha256": hashlib.sha256(_canonical(grant.signed_fields())).hexdigest(),
                },
            )
            records[approval_id] = record
            self._save(records)
            return ApprovalRecord(**record)

    def consume(
        self,
        approval_id: str,
        *,
        session_id: str,
        capability: str,
        tool: str,
        target: str,
        args: dict[str, Any],
    ) -> ApprovalRecord:
        """Atomically validate, consume, and mark RESUMED before any side effect."""
        with self._lock:
            records = self._load()
            if approval_id not in records:
                raise KeyError(f"unknown approval id: {approval_id}")
            record = records[approval_id]
            if record["status"] not in {"APPROVED", "RESUMED"}:
                raise PermissionError(f"approval is not consumable in state {record['status']}")
            persisted = ApprovalRecord(**record)
            verification = self._verify_record(persisted)
            if not verification["valid"]:
                raise PermissionError(f"approval integrity failure: {verification['errors']}")
            observed = ApprovalBinding(
                approval_id,
                session_id,
                capability,
                tool,
                target,
                normalized_args_hash(args),
            )
            if observed != persisted.binding():
                raise PermissionError("approval target, arguments, or session binding mismatch")
            if persisted.expires_at is None or datetime.fromisoformat(persisted.expires_at) <= datetime.now(timezone.utc):
                raise PermissionError("approval grant is expired")
            if persisted.usage_count >= persisted.usage_limit:
                raise PermissionError("approval usage limit exhausted")
            record["usage_count"] = persisted.usage_count + 1
            record["status"] = "RESUMED"
            record["updated_at"] = _now()
            self._append_event(
                record,
                "RESUMED",
                {
                    "usage_count": record["usage_count"],
                    "usage_limit": persisted.usage_limit,
                    "arguments_hash": persisted.arguments_hash,
                    "consumed_before_side_effect": True,
                },
            )
            records[approval_id] = record
            self._save(records)
            return ApprovalRecord(**record)

    def attach_execution_result(self, approval_id: str, result: dict[str, Any]) -> ApprovalRecord:
        with self._lock:
            records = self._load()
            record = records.get(approval_id)
            if record is None:
                raise KeyError(f"unknown approval id: {approval_id}")
            if record["status"] != "RESUMED":
                raise ValueError("execution result can only be attached to a resumed approval")
            record["execution_result"] = result
            record["updated_at"] = _now()
            records[approval_id] = record
            self._save(records)
            return ApprovalRecord(**record)

    def reject(self, approval_id: str, *, rejected_by: str, trusted_origin: str) -> ApprovalRecord:
        if trusted_origin not in self._trusted_origins or not rejected_by.strip():
            raise PermissionError("rejection must come from a trusted origin")
        with self._lock:
            records = self._load()
            record = records.get(approval_id)
            if record is None:
                raise KeyError(f"unknown approval id: {approval_id}")
            if record["status"] != "PAUSED":
                raise ValueError(f"invalid approval transition: {record['status']} -> REJECTED")
            record["status"] = "REJECTED"
            record["updated_at"] = _now()
            self._append_event(record, "REJECTED", {"rejected_by": rejected_by, "trusted_origin": trusted_origin})
            record["status"] = "TERMINATED"
            record["updated_at"] = _now()
            self._append_event(record, "TERMINATED", {"side_effect_permitted": False})
            records[approval_id] = record
            self._save(records)
            return ApprovalRecord(**record)

    def _verify_record(self, record: ApprovalRecord) -> dict[str, Any]:
        previous = "0" * 64
        errors: list[str] = []
        for index, event in enumerate(record.events):
            candidate = dict(event)
            observed = candidate.pop("event_hash", None)
            expected = hashlib.sha256(_canonical(candidate)).hexdigest()
            if event.get("sequence") != index or event.get("prev_hash") != previous or observed != expected:
                errors.append(f"event_{index}_hash_chain_invalid")
            previous = str(observed)
        if record.events:
            initial = record.events[0].get("payload", {})
            expected_bindings = {
                "session_id": record.session_id,
                "runner_id": record.runner_id,
                "capability": record.capability,
                "tool": record.tool,
                "target": record.target,
                "request_sha256": hashlib.sha256(_canonical(record.request)).hexdigest(),
                "arguments_hash": normalized_args_hash(record.args),
            }
            for key, expected in expected_bindings.items():
                if initial.get(key) != expected:
                    errors.append(f"{key}_binding_mismatch")
        if record.arguments_hash != normalized_args_hash(record.args):
            errors.append("executor_args_mismatch")
        if record.grant is not None:
            try:
                grant = ApprovalGrant(**record.grant)
            except (TypeError, ValueError):
                errors.append("grant_schema_invalid")
            else:
                if not self._verify_grant_signature(grant):
                    errors.append("grant_signature_invalid")
                if ApprovalBinding(
                    grant.approval_id,
                    grant.session_id,
                    grant.capability,
                    grant.tool,
                    grant.target,
                    grant.arguments_hash,
                ) != record.binding():
                    errors.append("grant_binding_mismatch")
                if grant.trusted_origin not in self._trusted_origins:
                    errors.append("grant_origin_untrusted")
                if (record.once, record.usage_limit, record.expires_at, record.created_by, record.trusted_origin) != (
                    grant.once,
                    grant.usage_limit,
                    grant.expires_at,
                    grant.created_by,
                    grant.trusted_origin,
                ):
                    errors.append("grant_metadata_mismatch")
        if record.usage_count < 0 or record.usage_count > record.usage_limit:
            errors.append("usage_count_invalid")
        return {
            "approval_id": record.approval_id,
            "valid": not errors,
            "event_count": len(record.events),
            "session_root": previous,
            "errors": errors,
        }

    def verify(self, approval_id: str) -> dict[str, Any]:
        with self._lock:
            return self._verify_record(self.get(approval_id))
