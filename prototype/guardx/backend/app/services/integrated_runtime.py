from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.authorization_runtime import AuthorizationRuntime
from app.contracts import ApprovalResumeEnvelope, PlannedActionEnvelope


class PlannerAuthorizationBindingError(PermissionError):
    pass


@dataclass(frozen=True)
class IntegratedRuntimeService:
    """Production application boundary; never exposes SecureExecutor directly."""

    authorization_runtime: AuthorizationRuntime

    def execute_planned_action(self, envelope: PlannedActionEnvelope) -> dict[str, Any]:
        matches = [step for step in envelope.plan.steps if step.step_id == envelope.step_id]
        if len(matches) != 1:
            raise PlannerAuthorizationBindingError("planned step identity is missing or ambiguous")
        step = matches[0]
        context = envelope.authorization_context
        if not step.trust_boundary.executable:
            raise PlannerAuthorizationBindingError("planned step is not executable")
        if step.capability != context.requested_capability:
            raise PlannerAuthorizationBindingError("planner capability does not match authorization context")
        planned_tool = step.constraints.get("tool")
        proposed_tool = context.proposed_action.get("tool")
        if planned_tool is not None and planned_tool != proposed_tool:
            raise PlannerAuthorizationBindingError("planner tool does not match proposed action")
        return self.authorization_runtime.run(
            execution_id=envelope.execution_id,
            session_id=envelope.session_id,
            request=context,
            args=envelope.args,
        )

    def resume_approved_action(self, envelope: ApprovalResumeEnvelope) -> dict[str, Any]:
        return self.authorization_runtime.resume(
            envelope.approval_id,
            session_id=envelope.session_id,
            capability=envelope.capability,
            tool=envelope.tool,
            target=envelope.target,
            args=envelope.args,
        )
