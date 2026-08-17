from __future__ import annotations

import hashlib
import json
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from app.contracts import AuthorizationContext, AuthorizationFinding


class ContinuationPlan(BaseModel):
    """Side-effect-free handoff contract for later R4-A/R4-C integration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "guardx-deterministic-continuation-v1"
    status: str
    control_flow: Literal[
        "CONTINUE",
        "QUARANTINE_AND_CONTINUE",
        "PAUSE_FOR_APPROVAL",
        "TERMINATE",
        "COMPLETED",
    ]
    context_id: str
    original_goal: str
    quarantined_action_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    allowed_inputs: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
    capability_effective: bool = False
    capability_mint_rejected: bool = False


@runtime_checkable
class DeterministicContinuationHook(Protocol):
    hook_id: str

    def plan(self, context: AuthorizationContext, finding: AuthorizationFinding) -> ContinuationPlan:
        ...


class DefaultContinuationHook:
    """Produces a deterministic plan only; it never calls a tool or executor."""

    hook_id = "default_no_execution_continuation"

    def plan(self, context: AuthorizationContext, finding: AuthorizationFinding) -> ContinuationPlan:
        model_capability_claim = finding.evidence.get("model_capability_claim") is True
        capability_mint_rejected = model_capability_claim and not finding.capability_granted
        if finding.decision == "QUARANTINE_AND_CONTINUE":
            control_flow = "QUARANTINE_AND_CONTINUE"
            status = "eligible"
            reasons = ["proposed_action_quarantined", "original_task_preserved"]
        elif finding.decision == "REQUIRE_APPROVAL":
            if context.approval_state == "approved":
                completed = context.action_origin == "user_goal"
                control_flow = "COMPLETED" if completed else "CONTINUE"
                status = "completed" if completed else "continue"
                reasons = ["scoped_approval_verified"]
            elif context.approval_state == "denied":
                terminal = context.action_origin == "user_goal"
                control_flow = "TERMINATE" if terminal else "QUARANTINE_AND_CONTINUE"
                status = "terminated" if terminal else "eligible"
                reasons = ["approval_denied"]
            else:
                control_flow = "PAUSE_FOR_APPROVAL"
                status = "paused"
                reasons = ["trusted_approval_required"]
        elif finding.decision == "TERMINATE":
            control_flow = "TERMINATE"
            status = "terminated"
            reasons = ["policy_terminated"]
        elif finding.decision == "DENY_ACTION":
            terminal = context.action_origin == "user_goal"
            control_flow = "TERMINATE" if terminal else "QUARANTINE_AND_CONTINUE"
            status = "terminated" if terminal else "eligible"
            reasons = ["forbidden_user_goal" if terminal else "current_action_denied_original_task_preserved"]
        elif finding.decision in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}:
            completed = context.action_origin == "user_goal"
            control_flow = "COMPLETED" if completed else "CONTINUE"
            status = "completed" if completed else "continue"
            reasons = ["terminal_user_goal_action_authorized" if completed else "authorized_intermediate_action"]
        else:  # pragma: no cover - contract validation makes this unreachable
            control_flow = "TERMINATE"
            status = "terminated"
            reasons = ["unrecognized_authorization_state"]

        if control_flow != "QUARANTINE_AND_CONTINUE":
            return ContinuationPlan(
                status=status,
                control_flow=control_flow,
                context_id=context.context_id,
                original_goal=context.user_goal,
                allowed_inputs=[],
                reasons=reasons,
                capability_effective=finding.capability_granted,
                capability_mint_rejected=capability_mint_rejected,
                metadata={
                    "hook_id": self.hook_id,
                    "action_origin": context.action_origin,
                    "task_lifecycle": context.task_lifecycle,
                    "approval_state": context.approval_state,
                },
            )
        canonical_action = json.dumps(
            context.proposed_action,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return ContinuationPlan(
            status="eligible",
            control_flow="QUARANTINE_AND_CONTINUE",
            context_id=context.context_id,
            original_goal=context.user_goal,
            quarantined_action_sha256=hashlib.sha256(canonical_action).hexdigest(),
            allowed_inputs=["user_goal", "sanitized_observation_facts"],
            reasons=reasons,
            capability_effective=finding.capability_granted,
            capability_mint_rejected=capability_mint_rejected,
            metadata={
                "hook_id": self.hook_id,
                "action_origin": context.action_origin,
                "task_lifecycle": context.task_lifecycle,
                "approval_state": context.approval_state,
            },
        )
