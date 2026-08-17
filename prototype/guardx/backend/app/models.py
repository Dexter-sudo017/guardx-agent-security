from typing import Any

from pydantic import BaseModel, Field

from app.contracts import ExecutionLifecycleReport, ExecutionReport, PolicyDecision, RiskFinding


class Message(BaseModel):
    role: str = Field(default="user")
    content: str


class GuardedChatRequest(BaseModel):
    session_id: str = Field(default="default-session")
    model: str | None = None
    message: str
    history: list[Message] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class GuardedRagRequest(GuardedChatRequest):
    context_chunks: list[str] = Field(default_factory=list)


class RagDemoDocument(BaseModel):
    source: str = Field(default="reviewer-document", max_length=240)
    text: str = Field(min_length=1, max_length=100000)


class GuardedRagDemoRequest(BaseModel):
    session_id: str = Field(default="default-rag-session")
    model: str = Field(default="local-ollama-qwen2_5-7b")
    message: str = Field(min_length=1, max_length=6000)
    documents: list[RagDemoDocument] = Field(min_length=1, max_length=12)
    top_k: int = Field(default=4, ge=1, le=8)


class GuardedVlmOcrRequest(GuardedChatRequest):
    image_id: str = Field(default="local-image")
    ocr_text: str = ""
    vlm_answer: str | None = None


class GuardedVlmImageRequest(BaseModel):
    session_id: str = Field(default="default-vlm-session")
    message: str = Field(default="请提取图片文字并描述可见内容。", max_length=6000)
    image_base64: str
    mime_type: str = Field(default="image/png")
    filename: str = Field(default="uploaded-image")
    vlm_model: str = Field(default="qwen2.5vl:7b")
    downstream_model: str = Field(default="local-ollama-qwen2_5-7b")


class ToolCallRequest(BaseModel):
    session_id: str = Field(default="default-session")
    tool_name: str
    args: dict[str, Any] = Field(default_factory=dict)
    risk_hint: float | None = None


class ActionGuardRequest(BaseModel):
    schema_version: str = Field(default="guardx-agent-action-v1")
    replay_id: str = Field(default="")
    session_id: str = Field(default="default-session")
    agent: str = Field(default="generic-agent")
    surface: str = Field(default="tool")
    action: dict[str, Any] = Field(default_factory=dict)
    task_context: dict[str, Any] = Field(default_factory=dict)
    risk_hint: float | None = None


class AgentGuardedDemoRequest(BaseModel):
    session_id: str = Field(default="default-agent-demo-session")
    model: str
    user_goal: str = Field(min_length=1, max_length=6000)
    untrusted_observation: str = Field(default="", max_length=10000)
    surface: str = Field(default="tool")
    action: dict[str, Any] = Field(default_factory=dict)
    risk_hint: float | None = None


class ActionGuardResponse(BaseModel):
    schema_version: str = Field(default="guardx-agent-action-decision-v1")
    replay_id: str
    session_id: str
    agent: str
    surface: str
    allowed: bool
    mode: str
    reason: str
    tool_name: str
    risk_score: float
    sanitized_args: dict[str, Any] = Field(default_factory=dict)
    observation: str = ""
    latency_ms: float = 0.0
    risk_findings: list[RiskFinding] = Field(default_factory=list)
    policy_decision: PolicyDecision | None = None
    defense_actions: list[dict[str, Any]] = Field(default_factory=list)
    execution_report: ExecutionReport | None = None
    lifecycle_report: ExecutionLifecycleReport | None = None


class ActionObservationRequest(BaseModel):
    schema_version: str = Field(default="guardx-agent-observation-v1")
    replay_id: str = Field(default="")
    session_id: str = Field(default="default-session")
    agent: str = Field(default="generic-agent")
    surface: str = Field(default="tool")
    action: dict[str, Any] = Field(default_factory=dict)
    observation: str = ""
    target_status: str = Field(default="completed")
    metadata: dict[str, Any] = Field(default_factory=dict)


class ActionObservationResponse(BaseModel):
    schema_version: str = Field(default="guardx-agent-observation-audit-v1")
    replay_id: str
    session_id: str
    agent: str
    surface: str
    safe_to_return: bool
    mode: str
    sanitized_observation: str
    output_analysis: "AnalysisResult"
    latency_ms: float = 0.0
    risk_findings: list[RiskFinding] = Field(default_factory=list)
    policy_decision: PolicyDecision | None = None
    defense_actions: list[dict[str, Any]] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    risk_score: float
    labels: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class GuardedResponse(BaseModel):
    session_id: str
    model: str
    action: str
    answer: str
    upstream_model_output: str | None = None
    risk_score: float
    input_analysis: AnalysisResult
    embedding_analysis: AnalysisResult | None = None
    context_analysis: AnalysisResult | None = None
    output_analysis: AnalysisResult | None = None
    tool_decisions: list[dict[str, Any]] = Field(default_factory=list)
    risk_findings: list[RiskFinding] = Field(default_factory=list)
    policy_decision: PolicyDecision | None = None
    defense_actions: list[dict[str, Any]] = Field(default_factory=list)
    model_invoked: bool = False
    response_source: str = "guardx"


class ToolDecision(BaseModel):
    allowed: bool
    reason: str
    mode: str
    sanitized_args: dict[str, Any] = Field(default_factory=dict)
    rule_id: str = ""
    evidence: list[str] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)


class ModelInfo(BaseModel):
    name: str
    adapter_type: str
    description: str = ""
    configured: bool = True


ActionObservationResponse.model_rebuild()
