from typing import Any, Literal

from pydantic import BaseModel, Field

from app.contracts.execution import TrustBoundary


GuardSurface = Literal["chat", "rag", "agent_tool", "vlm", "eval"]
RiskType = Literal["jailbreak", "prompt_injection", "privacy_leakage", "tool_abuse", "unsafe_content"]
RiskSeverity = Literal["info", "low", "medium", "high", "critical"]


class RiskSegment(BaseModel):
    segment_id: str
    text: str
    trust_boundary: TrustBoundary


class RiskFinding(BaseModel):
    provider_id: str
    surface: GuardSurface | str
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_type: RiskType | str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: RiskSeverity
    evidence_refs: list[str] = Field(default_factory=list)
    features: dict[str, Any] = Field(default_factory=dict)
    latency_ms: float = Field(default=0.0, ge=0.0)
    model_version: str = "unknown"
