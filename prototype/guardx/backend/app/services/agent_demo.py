from fastapi import HTTPException

from app.audit.logger import log_action_decision
from app.models import AgentGuardedDemoRequest, ActionGuardRequest
from app.orchestration import run_action_decision_flow
from app.services.agent_risk import compute_agent_risk
from app.services.qwen_agent_planner import plan_with_qwen_agent
from app.services.runtime_state import adapter_registry, audit_store


def run_agent_planner_demo(request: AgentGuardedDemoRequest) -> dict:
    """Use Qwen-Agent for planning only; GuardX owns authorization and execution."""
    model_info = adapter_registry.get_info(request.model)
    if not model_info.configured or "agent_planner" not in model_info.capabilities:
        raise HTTPException(status_code=400, detail="Selected model is not a validated Qwen-Agent planner")
    try:
        planner = plan_with_qwen_agent(
            model_name=request.model,
            model_spec=adapter_registry.get_spec(request.model),
            user_goal=request.user_goal,
            observation=request.untrusted_observation,
            candidate=request.action,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Qwen-Agent planning failed: {exc}") from exc

    computed_risk = compute_agent_risk(
        user_goal=request.user_goal,
        untrusted_observation=request.untrusted_observation,
        action=planner["action"],
        approval_scope=request.approval_scope,
    )
    guard_request = ActionGuardRequest(
        schema_version="guardx-agent-action-v1",
        replay_id=f"agent-plan-{request.session_id}",
        session_id=request.session_id,
        agent=f"qwen-agent:{request.model}",
        surface="agent_tool",
        action=planner["action"],
        task_context={
            "user_goal": request.user_goal,
            "untrusted_observation": request.untrusted_observation,
            "planner_model": request.model,
            "planner_framework": planner["framework"],
            "trust_boundary": "qwen_agent_planner_to_action_guard",
            "attack_vector": "untrusted_agent_observation" if computed_risk["task_relation_conflict"] else "",
        },
        risk_hint=computed_risk["score"],
    )
    result = run_action_decision_flow(guard_request)
    log_action_decision(
        audit_store,
        request=guard_request,
        response=result.response,
        execution=result.execution,
        trace_events=result.trace_events,
        decision_record=result.decision_record,
    )
    lifecycle_events = result.response.lifecycle_report.events if result.response.lifecycle_report else []
    runner_invoked = any(item.phase == "execute" and item.status == "success" for item in lifecycle_events)
    side_effect = bool(runner_invoked and result.response.tool_name == "create_review_ticket_safe" and result.response.allowed)
    return {
        **result.response.model_dump(mode="json"),
        "agent_demo": True,
        "planner_framework": planner["framework"],
        "planner_model": request.model,
        "planner_model_invoked": True,
        "planner_output": planner["output"],
        "planner_messages": planner["messages"],
        "planner_action": planner["action"],
        "exposed_tools": planner["tool_contract"],
        "computed_risk": computed_risk,
        "risk_source": computed_risk["source"],
        "runner_invoked": runner_invoked,
        "side_effect": side_effect,
        "response_source": "qwen_agent_planner_then_guardx_action_guard",
    }
