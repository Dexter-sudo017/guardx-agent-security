from typing import Any, Literal

from pydantic import BaseModel, Field


PluginDeploymentMode = Literal["in_process", "sidecar_service"]


class PluginStatus(BaseModel):
    provider_id: str
    status: Literal["ok", "degraded", "unavailable"]
    deployment_mode: PluginDeploymentMode
    message: str = ""
    latency_ms: float = Field(default=0.0, ge=0.0)


class PluginManifest(BaseModel):
    provider_id: str
    name: str
    version: str = "unknown"
    deployment_modes: list[PluginDeploymentMode] = Field(default_factory=lambda: ["in_process"])
    capabilities: list[str] = Field(default_factory=list)
    model_versions: dict[str, str] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)
