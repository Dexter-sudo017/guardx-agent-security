from typing import Protocol

from pydantic import BaseModel, Field

from app.contracts import PluginManifest, PluginStatus, RiskFinding, RiskSegment


class RiskProviderRequest(BaseModel):
    request_id: str
    session_id: str
    surface: str
    segments: list[RiskSegment] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class RiskProvider(Protocol):
    provider_id: str

    def score(self, request: RiskProviderRequest, segments: list[RiskSegment]) -> list[RiskFinding]:
        ...

    def health(self) -> PluginStatus:
        ...

    def metadata(self) -> PluginManifest:
        ...
