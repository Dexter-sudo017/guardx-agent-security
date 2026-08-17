from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CapabilityGrant(BaseModel):
    """A grant issued outside the semantic/model plane."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    grant_id: str
    subject_id: str
    capability: str
    issuer: str
    issued_at: datetime
    expires_at: datetime | None = None
    revoked: bool = False
    constraints: dict[str, Any] = Field(default_factory=dict)
    provenance: Literal["trusted_capability_store"] = "trusted_capability_store"

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("capability timestamps must be timezone-aware")
        return value


class CapabilityVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    granted: bool
    grant: CapabilityGrant | None = None
    reason: str
    constraints_satisfied: bool = False
    violations: list[str] = Field(default_factory=list)
    store_id: str
    store_sha256: str
