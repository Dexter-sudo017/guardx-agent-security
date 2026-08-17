from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class CapabilityVerification:
    granted: bool
    grant_reference: str | None = None
    reason: str = ""


class CapabilityVerifier(Protocol):
    def verify(self, *, session_id: str, capability: str, tool: str, target: str) -> CapabilityVerification: ...


@dataclass(frozen=True)
class StaticCapabilityGrant:
    session_id: str
    capability: str
    tool: str
    target: str
    grant_reference: str


class StaticCapabilityVerifier:
    """Test/dev verifier. Production must inject its authoritative capability store."""

    def __init__(self, grants: list[StaticCapabilityGrant] | None = None) -> None:
        self._grants = list(grants or [])

    def verify(self, *, session_id: str, capability: str, tool: str, target: str) -> CapabilityVerification:
        for grant in self._grants:
            if (grant.session_id, grant.capability, grant.tool, grant.target) == (session_id, capability, tool, target):
                return CapabilityVerification(True, grant.grant_reference, "exact capability binding matched")
        return CapabilityVerification(False, None, "no exact session/capability/tool/target grant")
