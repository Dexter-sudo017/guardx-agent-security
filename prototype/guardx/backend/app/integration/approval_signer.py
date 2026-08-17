from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from app.approval import ApprovalBinding, ApprovalGrant, ApprovalSigner


@dataclass(frozen=True)
class ApprovalGrantPolicy:
    ttl_seconds: float = 300.0
    once: bool = True
    usage_count: int = 1


@dataclass(frozen=True)
class TrustedOperatorIdentity:
    created_by: str
    trusted_origin: str


class ApprovalSignerBackend(Protocol):
    signer_kind: str

    def issue(self, binding: ApprovalBinding, policy: ApprovalGrantPolicy) -> ApprovalGrant: ...
    def operator_identity(self) -> TrustedOperatorIdentity: ...


class TestDevApprovalSigner:
    """Explicit test/dev implementation; its key must be injected, never committed."""

    signer_kind = "test_dev_hmac"

    def __init__(self, secret: bytes, *, created_by: str = "test-dev-operator") -> None:
        self._signer = ApprovalSigner(secret)
        self._identity = TrustedOperatorIdentity(created_by, "trusted_operator")

    def issue(self, binding: ApprovalBinding, policy: ApprovalGrantPolicy) -> ApprovalGrant:
        return self._signer.issue(
            binding,
            created_by=self._identity.created_by,
            trusted_origin=self._identity.trusted_origin,
            ttl_seconds=policy.ttl_seconds,
            once=policy.once,
            usage_count=policy.usage_count,
        )

    def operator_identity(self) -> TrustedOperatorIdentity:
        return self._identity


class AuthenticatedOperatorApprovalSigner:
    """Production port: authentication and signing remain behind injected callbacks."""

    signer_kind = "production_authenticated_operator"

    def __init__(
        self,
        *,
        issue_callback: Callable[[ApprovalBinding, ApprovalGrantPolicy], ApprovalGrant],
        identity_callback: Callable[[], TrustedOperatorIdentity],
    ) -> None:
        self._issue_callback = issue_callback
        self._identity_callback = identity_callback

    def issue(self, binding: ApprovalBinding, policy: ApprovalGrantPolicy) -> ApprovalGrant:
        return self._issue_callback(binding, policy)

    def operator_identity(self) -> TrustedOperatorIdentity:
        return self._identity_callback()
