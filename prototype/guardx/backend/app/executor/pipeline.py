from __future__ import annotations

from typing import Any

from app.executor.action_mapping import normalize_action_to_tool
from app.executor.artifacts import bounded_risk, execution_key, execution_plan, execution_report
from app.executor.context_metadata import attach_guardx_context
from app.executor.review_models import ActionExecutionReview
from app.executor.runtime import run_executor_lifecycle
from app.risk_providers import action_guard_risk_finding, denied_action_policy_decision, policy_decision_for_findings


def _review_prepared_tool(
    *,
    session_id: str,
    surface: str,
    tool_name: str,
    mapped_args: dict[str, Any],
    risk_score: float,
    replay_id: str = "",
    execution_context: dict[str, Any] | None = None,
) -> ActionExecutionReview:
    risk_value = bounded_risk(risk_score)
    context = execution_context or {}
    review_args = attach_guardx_context(mapped_args, context)
    key = execution_key(
        {
            "session_id": session_id,
            "surface": surface,
            "tool_name": tool_name,
            "mapped_args": review_args,
            "risk_score": risk_value,
            "replay_id": replay_id,
            "execution_context": context,
        }
    )
    plan = execution_plan(
        execution_key=key,
        session_id=session_id,
        surface=surface,
        tool_name=tool_name,
        risk_score=risk_value,
        replay_id=replay_id,
    )
    lifecycle = run_executor_lifecycle(
        execution_key=key,
        session_id=session_id,
        surface=surface,
        tool_name=tool_name,
        mapped_args=review_args,
        risk_score=risk_value,
    )
    decision = lifecycle.decision
    risk_findings = [
        action_guard_risk_finding(
            surface=surface,
            tool_name=tool_name,
            risk_score=risk_value,
            decision=decision,
            latency_ms=lifecycle.precheck_latency_ms,
        )
    ]
    policy_decision = policy_decision_for_findings(risk_value, risk_findings)
    if not decision.allowed:
        policy_decision = denied_action_policy_decision(policy_decision, risk_findings[0])
    return ActionExecutionReview(
        execution_key=key,
        execution_plan=plan,
        execution_report=execution_report(
            execution_key=key,
            tool_name=tool_name,
            decision=decision,
            latency_ms=lifecycle.precheck_latency_ms,
            error=lifecycle.review_error or lifecycle.execution_error,
        ),
        session_id=session_id,
        surface=surface,
        tool_name=tool_name,
        mapped_args=review_args,
        risk_score=risk_value,
        decision=decision,
        observation=lifecycle.observation,
        latency_ms=lifecycle.total_latency_ms,
        risk_findings=risk_findings,
        policy_decision=policy_decision,
        lifecycle_report=lifecycle.lifecycle_report,
    )


def review_action_request(
    *,
    session_id: str,
    surface: str,
    action: dict[str, Any],
    risk_score: float,
    replay_id: str = "",
    task_context: dict[str, Any] | None = None,
) -> ActionExecutionReview:
    tool_name, mapped_args = normalize_action_to_tool(surface, action)
    prepared_args = dict(mapped_args)
    prepared_args["_guardx_surface"] = surface
    if replay_id:
        prepared_args["_guardx_replay_id"] = replay_id
    return _review_prepared_tool(
        session_id=session_id,
        surface=surface,
        tool_name=tool_name,
        mapped_args=prepared_args,
        risk_score=risk_score,
        replay_id=replay_id,
        execution_context=task_context,
    )


def review_tool_request(
    *,
    session_id: str,
    tool_name: str,
    args: dict[str, Any],
    risk_score: float,
    surface: str = "agent_tool",
    replay_id: str = "",
    execution_context: dict[str, Any] | None = None,
) -> ActionExecutionReview:
    return _review_prepared_tool(
        session_id=session_id,
        surface=surface,
        tool_name=tool_name,
        mapped_args=dict(args),
        risk_score=risk_score,
        replay_id=replay_id,
        execution_context=execution_context,
    )
