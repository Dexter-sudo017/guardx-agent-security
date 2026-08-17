from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from app.contracts.execution import ExecutionLifecycleReport, ExecutionPlan, ExecutionReport
from app.contracts.policy import PolicyDecision
from app.contracts.risk import RiskFinding, RiskSegment
from app.contracts.trace import ExperimentContext, TraceEvent


RuntimeFlow = Literal["chat", "rag", "vlm_ocr", "agent_tool", "proxy", "baseline", "eval"]
LifecycleStage = Literal["input", "risk", "policy", "generation", "executor", "observation", "output", "audit", "error"]


class GuardedRuntimeEnvelope(BaseModel):
    schema_version: str = "guardx-runtime-envelope-v1"
    request_id: str = Field(default_factory=lambda: f"gx-request-{uuid4().hex}")
    session_id: str
    flow: RuntimeFlow | str
    surface: str
    model: str | None = None
    segments: list[RiskSegment] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    experiment: ExperimentContext = Field(default_factory=ExperimentContext)


class GuardedDecisionRecord(BaseModel):
    schema_version: str = "guardx-decision-record-v1"
    request_id: str
    trace_id: str
    stage: LifecycleStage | str
    surface: str
    envelope: GuardedRuntimeEnvelope
    risk_findings: list[RiskFinding] = Field(default_factory=list)
    policy_decision: PolicyDecision
    execution_plan: ExecutionPlan | None = None
    execution_report: ExecutionReport | None = None
    lifecycle_report: ExecutionLifecycleReport | None = None
    trace_events: list[TraceEvent] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
