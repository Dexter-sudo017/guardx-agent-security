from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.contracts.execution import ExecutionPlan
from app.contracts.policy import AuthorizationContext


class PlannedActionEnvelope(BaseModel):
    """Planner-to-authorization handoff for every real side-effect action."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "guardx-planned-action-envelope-v1"
    execution_id: str
    session_id: str
    plan: ExecutionPlan
    step_id: str
    authorization_context: AuthorizationContext
    args: dict[str, Any] = Field(default_factory=dict)


class ApprovalResumeEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "guardx-approval-resume-envelope-v1"
    approval_id: str
    session_id: str
    capability: str
    tool: str
    target: str
    args: dict[str, Any] = Field(default_factory=dict)
