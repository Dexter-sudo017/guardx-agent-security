from time import perf_counter

from app.contracts import ExecutionPlan, PlanStep, PlannerOutput, PlannerRequest, PlannerTrace, TraceEvent
from app.observability import make_trace_event


class DeterministicPlanner:
    planner_id = "guardx_deterministic_planner"

    def plan(self, request: PlannerRequest) -> PlannerOutput:
        started = perf_counter()
        steps = [
            PlanStep(
                step_id=f"inspect_segment_{index}",
                capability="risk_context_review",
                input_ref=segment.segment_id,
                constraints={
                    "surface": request.context.surface,
                    "goal": request.context.goal,
                    "executable": segment.trust_boundary.executable,
                },
                rollback={},
                trust_boundary=segment.trust_boundary,
            )
            for index, segment in enumerate(request.context.segments)
        ]
        plan = ExecutionPlan(
            plan_id=f"gx-plan-{request.request_id}",
            planner_id=self.planner_id,
            steps=steps,
            risk_hints=[f"surface={request.context.surface}", f"segments={len(request.context.segments)}"],
            assumptions=["Planner emits contracts only; Executor owns enforcement."],
        )
        planner_trace = PlannerTrace(
            planner_id=self.planner_id,
            strategy="deterministic_segment_review",
            assumptions=plan.assumptions,
            context_refs=[segment.segment_id for segment in request.context.segments],
            latency_ms=round((perf_counter() - started) * 1000.0, 3),
        )
        trace_event = make_trace_event(
            trace_id=str(request.context.metadata.get("trace_id") or request.request_id),
            stage="planner",
            payload_ref=f"{request.context.session_id}:planner",
            execution_plan=plan,
            metadata=request.context.metadata,
        )
        return PlannerOutput(
            request_id=request.request_id,
            planner_id=self.planner_id,
            execution_plan=plan,
            planner_trace=planner_trace,
            trace_events=[TraceEvent.model_validate(trace_event)],
        )
