from fastapi import APIRouter

from app.audit.logger import log_action_decision, log_action_observation
from app.models import AgentGuardedDemoRequest, ActionGuardRequest, ActionGuardResponse, ActionObservationRequest, ActionObservationResponse
from app.orchestration import run_action_decision_flow, run_action_observation_flow
from app.services.agent_demo import run_agent_planner_demo
from app.services.runtime_state import audit_store

router = APIRouter()


@router.post("/v1/action_guard/request", response_model=ActionGuardResponse)
@router.post("/v1/action_guard/decide", response_model=ActionGuardResponse)
def action_guard_decide(request: ActionGuardRequest) -> ActionGuardResponse:
    result = run_action_decision_flow(request)
    log_action_decision(
        audit_store,
        request=request,
        response=result.response,
        execution=result.execution,
        trace_events=result.trace_events,
        decision_record=result.decision_record,
    )
    return result.response


@router.post("/v1/agent/plan_and_guard")
def agent_plan_and_guard(request: AgentGuardedDemoRequest) -> dict:
    return run_agent_planner_demo(request)


@router.post("/v1/action_guard/observe", response_model=ActionObservationResponse)
def action_guard_observe(request: ActionObservationRequest) -> ActionObservationResponse:
    result = run_action_observation_flow(request)
    log_action_observation(
        audit_store,
        request=request,
        response=result.response,
        trace_events=result.trace_events,
        decision_record=result.decision_record,
    )
    return result.response
