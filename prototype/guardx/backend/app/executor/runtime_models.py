from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from app.contracts import ExecutionLifecycleReport
from app.models import ToolDecision


PrecheckFn = Callable[[str, dict[str, Any], float], ToolDecision]


@dataclass(frozen=True)
class ToolExecutionOutcome:
    output_ref: str
    observation: str
    metadata: dict[str, Any] = field(default_factory=dict)


class ToolRunner(Protocol):
    def run(self, *, execution_key: str, tool_name: str, args: dict[str, Any]) -> ToolExecutionOutcome:
        ...

    def rollback(self, *, execution_key: str, tool_name: str, args: dict[str, Any], error: str) -> ToolExecutionOutcome:
        ...


@dataclass(frozen=True)
class ExecutorLifecycleRun:
    decision: ToolDecision
    lifecycle_report: ExecutionLifecycleReport
    observation: str
    precheck_latency_ms: float
    total_latency_ms: float
    review_error: str | None = None
    execution_error: str | None = None
