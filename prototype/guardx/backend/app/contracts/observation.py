from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from app.contracts.execution import TrustBoundary


ObservationSource = Literal["rag_document", "ocr_observation", "vlm_observation", "tool_output", "web_content"]


class ObservationProvenance(BaseModel):
    source_uri: str
    producer: str
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    metadata: dict[str, Any] = Field(default_factory=dict)


class ObservationEnvelope(BaseModel):
    schema_version: str = "guardx-observation-envelope-v1"
    observation_id: str
    source: ObservationSource | str
    content: str
    provenance: ObservationProvenance
    trust_boundary: TrustBoundary = Field(
        default_factory=lambda: TrustBoundary(source="ocr", trust_level="untrusted", executable=False, can_instruct_model=False)
    )

    def as_authorization_context(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "source_trust": self.trust_boundary.trust_level,
            "observation": self.content,
            "provenance": self.provenance.model_dump(mode="json"),
            "executable": self.trust_boundary.executable,
            "can_instruct_model": self.trust_boundary.can_instruct_model,
        }
