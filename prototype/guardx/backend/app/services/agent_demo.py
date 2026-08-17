import json

from fastapi import HTTPException

from app.audit.logger import log_action_decision
from app.models import AgentGuardedDemoRequest, ActionGuardRequest
from app.orchestration import run_action_decision_flow
from app.services.runtime_state import adapter_registry, audit_store


def run_agent_planner_demo(request: AgentGuardedDemoRequest) -> dict:
    """Call a powerless planner model, then enforce the explicit action candidate."""
    model_info = adapter_registry.get_info(request.model)
    if not model_info.configured or model_info.adapter_type == "mock":
        raise HTTPException(status_code=400, detail="Selected planner model is not configured")
    planner_prompt = (
        "你是 GuardX 演示中的只读 Agent 规划器。你没有工具和执行权限。\n"
        "请根据用户目标、工具或检索观察以及候选动作，说明你准备请求什么动作。"
        "不要声称动作已经执行，也不要省略风险相关字段。完整保留候选 JSON。\n\n"
        f"用户目标：\n{request.user_goal}\n\n"
        f"非可信观察：\n{request.untrusted_observation or '（无）'}\n\n"
        f"候选动作 JSON：\n{json.dumps(request.action, ensure_ascii=False, indent=2)}"
    )
    try:
        planner_output = adapter_registry.get(request.model).generate(planner_prompt, [], request.model)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Planner model request failed: {exc}") from exc

    guard_request = ActionGuardRequest(
        schema_version="guardx-agent-action-v1",
        replay_id=f"agent-plan-{request.session_id}",
        session_id=request.session_id,
        agent=f"planner:{request.model}",
        surface=request.surface,
        action=request.action,
        task_context={
            "user_goal": request.user_goal,
            "untrusted_observation": request.untrusted_observation,
            "planner_model": request.model,
            "planner_output": planner_output,
            "trust_boundary": "powerless_planner_to_action_guard",
        },
        risk_hint=request.risk_hint,
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
    return {
        **result.response.model_dump(mode="json"),
        "agent_demo": True,
        "planner_model": request.model,
        "planner_model_invoked": True,
        "planner_output": planner_output,
        "response_source": "guardx_agent_planner_then_action_guard",
    }
