from dataclasses import dataclass
from typing import Literal

from app.contracts import GuardedDecisionRecord
from app.models import GuardedResponse


GuardedResponseFlow = Literal["chat", "rag", "vlm_ocr"]


@dataclass(frozen=True)
class GuardedRouteResult:
    flow: GuardedResponseFlow
    response: GuardedResponse
    trace_events: list[dict]
    decision_record: GuardedDecisionRecord | None = None
