from typing import Any, Literal

from pydantic import BaseModel, Field


TraceStage = Literal["input", "planner", "policy", "executor", "observation", "output", "error"]


class ExperimentContext(BaseModel):
    suite_id: str | None = None
    case_id: str | None = None
    policy_profile: str | None = None
    plugin_versions: dict[str, str] = Field(default_factory=dict)
    thresholds: dict[str, float] = Field(default_factory=dict)
    seed: int | None = None


class TraceEvent(BaseModel):
    trace_id: str
    span_id: str
    stage: TraceStage
    payload_ref: str | None = None
    risk_snapshot: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    experiment: ExperimentContext = Field(default_factory=ExperimentContext)
