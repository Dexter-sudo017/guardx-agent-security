from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from app.contracts import ExecutorCapability
from app.executor.agent_runners import ControlledReviewTicketRunner, EnterpriseKnowledgeSearchRunner
from app.executor.runners import LocalReadOnlySandboxRunner, SimulatedSafeToolRunner
from app.executor.runtime_models import ToolRunner


RunnerFactory = Callable[[], ToolRunner]
RUNNER_FACTORIES: dict[str, RunnerFactory] = {
    "local_readonly_sandbox": LocalReadOnlySandboxRunner,
    "simulated_safe_tool": SimulatedSafeToolRunner,
    "enterprise_knowledge_search": EnterpriseKnowledgeSearchRunner,
    "controlled_review_ticket": ControlledReviewTicketRunner,
}


@dataclass(frozen=True)
class RunnerSelection:
    runner_id: str
    runner: ToolRunner
    fallback_used: bool = False


def registered_runner_ids() -> list[str]:
    return sorted(RUNNER_FACTORIES)


def runner_for(capability: ExecutorCapability, *, fallback_runner_id: str = "simulated_safe_tool") -> RunnerSelection:
    requested = capability.runner or fallback_runner_id
    factory = RUNNER_FACTORIES.get(requested)
    if factory:
        return RunnerSelection(runner_id=requested, runner=factory())
    fallback = RUNNER_FACTORIES[fallback_runner_id]
    return RunnerSelection(runner_id=fallback_runner_id, runner=fallback(), fallback_used=True)
