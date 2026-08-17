from typing import Any, Literal

from pydantic import BaseModel, Field


BoundarySource = Literal["user", "retrieved_context", "ocr", "tool_output", "system", "developer"]
TrustLevel = Literal["trusted", "bounded", "untrusted"]
StepStatus = Literal["pending", "running", "success", "failed", "blocked", "timeout", "rolled_back"]
ReportStatus = Literal["success", "partial", "failed", "blocked", "timeout"]
ExecutionPhase = Literal["precheck", "execute", "observe", "rollback"]
ExecutionPhaseStatus = Literal["pending", "running", "success", "failed", "blocked", "timeout", "rolled_back", "skipped"]
ExecutorSideEffects = Literal["none", "read", "write", "network", "compute", "registration", "unknown"]


class TrustBoundary(BaseModel):
    source: BoundarySource | str
    trust_level: TrustLevel
    executable: bool = False
    can_instruct_model: bool = False


class PlanStep(BaseModel):
    step_id: str
    capability: str
    input_ref: str
    constraints: dict[str, Any] = Field(default_factory=dict)
    rollback: dict[str, Any] = Field(default_factory=dict)
    trust_boundary: TrustBoundary


class ExecutionPlan(BaseModel):
    plan_id: str
    planner_id: str
    steps: list[PlanStep] = Field(default_factory=list)
    risk_hints: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)


class StepResult(BaseModel):
    step_id: str
    status: StepStatus
    output_ref: str | None = None
    error: str | None = None
    latency_ms: float = Field(default=0.0, ge=0.0)


class ExecutionReport(BaseModel):
    plan_id: str
    status: ReportStatus
    step_results: list[StepResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    rollback_results: list[StepResult] = Field(default_factory=list)


class ExecutionLifecycleEvent(BaseModel):
    phase: ExecutionPhase
    status: ExecutionPhaseStatus
    input_ref: str | None = None
    output_ref: str | None = None
    error: str | None = None
    latency_ms: float = Field(default=0.0, ge=0.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExecutionLifecycleReport(BaseModel):
    execution_key: str
    status: ReportStatus
    events: list[ExecutionLifecycleEvent] = Field(default_factory=list)
    rollback_required: bool = False
    rollback_completed: bool = False


class ExecutorCapability(BaseModel):
    tool_name: str
    runner: str = "simulated_safe_tool"
    surfaces: list[str] = Field(default_factory=list)
    side_effects: ExecutorSideEffects = "unknown"
    requires_precheck: bool = True
    dry_run: bool = True
    rollback_supported: bool = False
    constraints: dict[str, Any] = Field(default_factory=dict)


class ExecutorCapabilityManifest(BaseModel):
    schema_version: str = "guardx-executor-capabilities-v1"
    default_runner: str = "simulated_safe_tool"
    capabilities: list[ExecutorCapability] = Field(default_factory=list)


class ExecutorRuntimePolicy(BaseModel):
    execution_timeout_ms: float = Field(default=10000.0, ge=0.0)
    max_retries: int = Field(default=0, ge=0)
    retry_backoff_ms: float = Field(default=0.0, ge=0.0)
    rollback_on_failure: bool = True
    rollback_timeout_ms: float = Field(default=5000.0, ge=0.0)


class ExecutorRuntimePolicyManifest(BaseModel):
    schema_version: str = "guardx-executor-runtime-policy-v1"
    default_policy: ExecutorRuntimePolicy = Field(default_factory=ExecutorRuntimePolicy)
    tools: dict[str, ExecutorRuntimePolicy] = Field(default_factory=dict)
