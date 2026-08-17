from typing import Protocol

from app.contracts import PlannerOutput, PlannerRequest


class Planner(Protocol):
    planner_id: str

    def plan(self, request: PlannerRequest) -> PlannerOutput:
        ...
