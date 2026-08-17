from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from app.contracts.capability import CapabilityGrant, CapabilityVerification
from app.contracts.policy import AuthorizationContext


class CapabilityStore:
    """Immutable deterministic grant store used by the hard verifier.

    It intentionally has no model-facing mint/update method. A new instance must
    be provisioned by trusted application code when grants change.
    """

    _KNOWN_CONSTRAINTS = {
        "allowed_destinations",
        "allowed_sinks",
        "data_classifications",
        "action_equals",
        "argument_equals",
    }

    def __init__(
        self,
        grants: Iterable[CapabilityGrant] = (),
        *,
        store_id: str = "in_memory_trusted_store",
        clock: Callable[[], datetime] | None = None,
        source_sha256: str | None = None,
    ) -> None:
        ordered = sorted(grants, key=lambda item: item.grant_id)
        grant_ids = [item.grant_id for item in ordered]
        if len(set(grant_ids)) != len(grant_ids):
            raise ValueError("duplicate capability grant_id")
        self._grants = tuple(ordered)
        self.store_id = store_id
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        canonical = json.dumps(
            [item.model_dump(mode="json") for item in self._grants],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.store_sha256 = source_sha256 or hashlib.sha256(canonical).hexdigest()

    @classmethod
    def from_json(cls, path: str | Path, *, clock: Callable[[], datetime] | None = None) -> "CapabilityStore":
        source = Path(path)
        raw = source.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        if payload.get("schema_version") != "guardx-capability-store-v1":
            raise ValueError("unsupported capability store schema")
        grants = [CapabilityGrant.model_validate(item) for item in payload.get("grants", [])]
        return cls(
            grants,
            store_id=str(payload.get("store_id") or source.name),
            clock=clock,
            source_sha256=hashlib.sha256(raw).hexdigest(),
        )

    def list_for_subject(self, subject_id: str) -> tuple[CapabilityGrant, ...]:
        return tuple(item for item in self._grants if item.subject_id == subject_id)

    def verify(self, context: AuthorizationContext) -> CapabilityVerification:
        candidates = [
            item
            for item in self._grants
            if item.subject_id == context.principal_id and item.capability == context.requested_capability
        ]
        if not candidates:
            return self._result(False, None, "grant_not_found", False, [])
        grant = candidates[0]
        now = self._clock()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        if grant.revoked:
            return self._result(False, grant, "grant_revoked", False, [])
        if grant.expires_at is not None and grant.expires_at <= now:
            return self._result(False, grant, "grant_expired", False, [])
        violations = self._constraint_violations(context, grant.constraints)
        if violations:
            return self._result(False, grant, "constraint_violation", False, violations)
        return self._result(True, grant, "grant_verified", True, [])

    def _result(
        self,
        granted: bool,
        grant: CapabilityGrant | None,
        reason: str,
        constraints_satisfied: bool,
        violations: list[str],
    ) -> CapabilityVerification:
        return CapabilityVerification(
            granted=granted,
            grant=grant,
            reason=reason,
            constraints_satisfied=constraints_satisfied,
            violations=violations,
            store_id=self.store_id,
            store_sha256=self.store_sha256,
        )

    def _constraint_violations(self, context: AuthorizationContext, constraints: dict[str, Any]) -> list[str]:
        unknown = sorted(set(constraints) - self._KNOWN_CONSTRAINTS)
        violations = [f"unknown_constraint:{item}" for item in unknown]
        if "allowed_destinations" in constraints and context.destination not in set(constraints["allowed_destinations"]):
            violations.append("destination_not_allowed")
        if "allowed_sinks" in constraints and context.sink not in set(constraints["allowed_sinks"]):
            violations.append("sink_not_allowed")
        if "data_classifications" in constraints and context.data_classification not in set(constraints["data_classifications"]):
            violations.append("data_classification_not_allowed")
        if "action_equals" in constraints:
            expected = constraints["action_equals"]
            if not isinstance(expected, dict):
                violations.append("invalid_action_equals")
            else:
                for key, value in expected.items():
                    if context.proposed_action.get(key) != value:
                        violations.append(f"action_mismatch:{key}")
        if "argument_equals" in constraints:
            expected_arguments = constraints["argument_equals"]
            actual_arguments = context.proposed_action.get("arguments")
            if not isinstance(expected_arguments, dict) or not isinstance(actual_arguments, dict):
                violations.append("invalid_argument_equals")
            else:
                for key, value in expected_arguments.items():
                    if actual_arguments.get(key) != value:
                        violations.append(f"argument_mismatch:{key}")
        return violations
