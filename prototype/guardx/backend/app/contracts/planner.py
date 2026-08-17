from typing import Any

from pydantic import BaseModel, Field

from app.contracts.execution import ExecutionPlan
from app.contracts.risk import RiskSegment
from app.contracts.trace import ExperimentContext, TraceEvent


class PlannerContext(BaseModel):
    session_id: str
    surface: str
    goal: str
    segments: list[RiskSegment] = Field(default_factory=list)
    memory_refs: list[str] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    experiment: ExperimentContext = Field(default_factory=ExperimentContext)


class PlannerRequest(BaseModel):
    schema_version: str = "guardx-planner-request-v1"
    request_id: str
    planner_id: str
    context: PlannerContext


class PlannerTrace(BaseModel):
    planner_id: str
    strategy: str
    assumptions: list[str] = Field(default_factory=list)
    context_refs: list[str] = Field(default_factory=list)
    latency_ms: float = Field(default=0.0, ge=0.0)


class PlannerOutput(BaseModel):
    schema_version: str = "guardx-planner-output-v1"
    request_id: str
    planner_id: str
    execution_plan: ExecutionPlan
    planner_trace: PlannerTrace
    trace_events: list[TraceEvent] = Field(default_factory=list)
