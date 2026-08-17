from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


EXECUTOR_CONTRACT_VERSION = "guardx-executor-service-v1"
APPROVAL_CONTRACT_VERSION = "guardx-approval-integration-v1"
CORE_V2_COMPATIBILITY_VERSION = "guardx-core-v2-executor-map-v1"

CanonicalDecision = Literal[
    "ALLOW",
    "ALLOW_WITH_CONSTRAINTS",
    "QUARANTINE_AND_CONTINUE",
    "REQUIRE_APPROVAL",
    "DENY_ACTION",
    "TERMINATE",
]
ExecutionState = Literal[
    "EXECUTED",
    "SKIPPED",
    "PAUSED",
    "RESUMED",
    "CONTINUING",
    "TERMINATED",
    "FAILED",
    "ROLLED_BACK",
]


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AuthorizationDecisionContract(StrictContract):
    decision: str = Field(min_length=1)
    source_version: str = Field(default="guardx-core-v2-unversioned", min_length=1)
    policy_reference: str | None = None
    constraints: dict[str, Any] = Field(default_factory=dict)


class ActionOrigin(StrictContract):
    authority: Literal[
        "policy_engine",
        "authenticated_user",
        "trusted_operator",
        "model_provider",
        "tool_output",
        "unknown",
    ]
    principal_id: str = Field(min_length=1)
    trusted: bool = False
    provenance_ref: str | None = None


class ExecutorServiceRequest(StrictContract):
    contract_version: Literal[EXECUTOR_CONTRACT_VERSION] = EXECUTOR_CONTRACT_VERSION
    session_id: str = Field(min_length=1)
    authorization_decision: AuthorizationDecisionContract
    capability: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    target: str = Field(min_length=1)
    arguments: dict[str, Any]
    action_origin: ActionOrigin
    approval_reference: str | None = None
    evidence_context: dict[str, Any] = Field(default_factory=dict)


class ExecutorServiceResponse(StrictContract):
    contract_version: Literal[EXECUTOR_CONTRACT_VERSION] = EXECUTOR_CONTRACT_VERSION
    execution_id: str
    session_id: str
    execution_state: ExecutionState
    executed: bool
    skipped: bool
    approval_required: bool
    approval_id: str | None = None
    side_effect_summary: dict[str, Any] = Field(default_factory=dict)
    pre_state_hash: str | None = None
    post_state_hash: str | None = None
    rollback_state: dict[str, Any] = Field(default_factory=lambda: {"state": "NOT_REQUESTED"})
    evidence_refs: list[str] = Field(default_factory=list)
    error_code: str | None = None


class ApprovalRequestCreate(StrictContract):
    contract_version: Literal[APPROVAL_CONTRACT_VERSION] = APPROVAL_CONTRACT_VERSION
    execution_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    capability: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    target: str = Field(min_length=1)
    arguments: dict[str, Any]
    request_context: dict[str, Any] = Field(default_factory=dict)


class ApprovalDecisionRequest(StrictContract):
    """A UI request, not a grant. Identity and signing are server-side."""

    contract_version: Literal[APPROVAL_CONTRACT_VERSION] = APPROVAL_CONTRACT_VERSION
    reason: str = Field(default="", max_length=1000)


class ApprovalInspectResponse(StrictContract):
    contract_version: Literal[APPROVAL_CONTRACT_VERSION] = APPROVAL_CONTRACT_VERSION
    approval_id: str
    execution_id: str
    session_id: str
    status: str
    capability: str
    tool: str
    target: str
    arguments_hash: str
    once: bool | None
    usage_limit: int
    usage_count: int
    expires_at: str | None
    created_by: str | None
    trusted_origin: str | None
    trace_states: list[str] = Field(default_factory=list)
    valid: bool
    validation_errors: list[str] = Field(default_factory=list)


class ApprovalValidationResponse(StrictContract):
    contract_version: Literal[APPROVAL_CONTRACT_VERSION] = APPROVAL_CONTRACT_VERSION
    approval_id: str
    valid: bool
    status: str
    usage_count: int
    usage_limit: int
    errors: list[str] = Field(default_factory=list)


class SessionExecutionTraceResponse(StrictContract):
    contract_version: Literal[EXECUTOR_CONTRACT_VERSION] = EXECUTOR_CONTRACT_VERSION
    session_id: str
    events: list[dict[str, Any]] = Field(default_factory=list)


class RollbackRequest(StrictContract):
    reason: str = Field(default="operator_requested", max_length=1000)
