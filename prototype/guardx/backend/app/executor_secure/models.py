from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PrecheckDecision:
    allowed: bool
    reason: str
    normalized_args: dict[str, Any]


@dataclass
class SecureExecutionResult:
    execution_id: str
    runner_id: str
    capability: str
    precheck_result: str
    permit_issued: bool
    runner_invocation_count: int
    before_state: str
    after_state: str
    side_effect_count: int
    output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    rollback: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    trace_root_hash: str = ""
    timings_ms: dict[str, float] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "runner_id": self.runner_id,
            "capability": self.capability,
            "precheck_result": self.precheck_result,
            "permit_issued": self.permit_issued,
            "runner_invocation_count": self.runner_invocation_count,
            "before_state": self.before_state,
            "after_state": self.after_state,
            "side_effect_count": self.side_effect_count,
            "output": self.output,
            "error": self.error,
            "rollback": self.rollback,
            "events": self.events,
            "trace_root_hash": self.trace_root_hash,
            "timings_ms": self.timings_ms,
        }
