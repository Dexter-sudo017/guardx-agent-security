from typing import Any

from pydantic import BaseModel, Field

from app.contracts import ExecutionLifecycleReport, ExecutionPlan, ExecutionReport, PolicyDecision, RiskFinding
from app.models import ToolDecision


class ActionExecutionReview(BaseModel):
    execution_key: str
    execution_plan: ExecutionPlan
    execution_report: ExecutionReport
    session_id: str
    surface: str
    tool_name: str
    mapped_args: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    decision: ToolDecision
    observation: str = ""
    latency_ms: float = 0.0
    risk_findings: list[RiskFinding] = Field(default_factory=list)
    policy_decision: PolicyDecision
    lifecycle_report: ExecutionLifecycleReport
