from __future__ import annotations

import hashlib

from app.contracts import ObservationEnvelope, ObservationProvenance, TrustBoundary
from app.models import GuardedVlmOcrRequest


def _envelope(*, image_id: str, kind: str, content: str, producer: str) -> ObservationEnvelope:
    source = "ocr_observation" if kind == "ocr" else "vlm_observation"
    return ObservationEnvelope(
        observation_id=f"{image_id}:{kind}",
        source=source,
        content=content,
        provenance=ObservationProvenance(
            source_uri=f"image:{image_id}#{kind}",
            producer=producer,
            content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        ),
        trust_boundary=TrustBoundary(source="ocr", trust_level="untrusted", executable=False, can_instruct_model=False),
    )


def build_vlm_observation_envelopes(request: GuardedVlmOcrRequest) -> list[ObservationEnvelope]:
    envelopes: list[ObservationEnvelope] = []
    if request.ocr_text:
        envelopes.append(_envelope(image_id=request.image_id, kind="ocr", content=request.ocr_text, producer="guardx_ocr_adapter"))
    if request.vlm_answer:
        envelopes.append(_envelope(image_id=request.image_id, kind="vlm", content=request.vlm_answer, producer="guardx_vlm_adapter"))
    return envelopes
