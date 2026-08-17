from dataclasses import dataclass
from time import perf_counter

from app.contracts import GuardedDecisionRecord
from app.executor import ActionExecutionReview, review_action_request
from app.guards import output_guard
from app.middleware.state import session_risk_state
from app.models import ActionGuardRequest, ActionGuardResponse, ActionObservationRequest, ActionObservationResponse
from app.observability import action_decision_trace_metadata, action_observation_trace_metadata, trace_events_for_executor_lifecycle, trace_events_for_policy, trace_id_from_metadata
from app.orchestration.action_lifecycle import action_observation_envelope, action_request_envelope
from app.orchestration.lifecycle import build_decision_record
from app.orchestration.observation_flow import observe_output_analysis
from app.services.action_observation_runtime import safe_observation_text
from app.services.defense_orchestrator import build_defense_actions, defense_trace_event


@dataclass(frozen=True)
class ActionDecisionFlowResult:
    response: ActionGuardResponse
    execution: ActionExecutionReview
    trace_events: list[dict]
    decision_record: GuardedDecisionRecord | None = None


@dataclass(frozen=True)
class ActionObservationFlowResult:
    response: ActionObservationResponse
    trace_events: list[dict]
    decision_record: GuardedDecisionRecord | None = None


def run_action_decision_flow(request: ActionGuardRequest) -> ActionDecisionFlowResult:
    session_id = request.session_id
    base_risk = session_risk_state[session_id]
    risk = request.risk_hint if request.risk_hint is not None else base_risk
    execution = review_action_request(
        session_id=session_id,
        surface=request.surface,
        action=request.action,
        risk_score=risk,
        replay_id=request.replay_id,
        task_context=request.task_context,
    )
    trace_metadata = action_decision_trace_metadata(
        task_context=request.task_context,
        replay_id=request.replay_id,
        agent=request.agent,
        surface=request.surface,
        execution_key=execution.execution_key,
    )
    runtime_envelope = action_request_envelope(request=request, execution_key=execution.execution_key, trace_metadata=trace_metadata)
    trace_id = trace_id_from_metadata(trace_metadata, fallback=request.replay_id or session_id)
    payload_ref = f"{session_id}:action_guard_decision"
    trace_events = trace_events_for_policy(
        trace_id=trace_id,
        payload_ref=payload_ref,
        risk_findings=execution.risk_findings,
        policy_decision=execution.policy_decision,
        metadata=trace_metadata,
        include_executor=True,
        execution_plan=execution.execution_plan,
        execution_report=execution.execution_report,
    )
    trace_events.extend(
        trace_events_for_executor_lifecycle(
            trace_id=trace_id,
            payload_ref=payload_ref,
            lifecycle_report=execution.lifecycle_report,
            metadata=trace_metadata,
        )
    )
    defense_actions = build_defense_actions(
        flow="action",
        policy_decision=execution.policy_decision,
        risk_findings=execution.risk_findings,
        trust_boundary="agent_tool_capability_boundary",
        execution_report=execution.execution_report,
        explicit_attack_vector=str(request.task_context.get("attack_vector", "")),
    )
    if defense_actions:
        trace_events.append(
            defense_trace_event(
                trace_id=trace_id,
                payload_ref=payload_ref,
                defense_actions=defense_actions,
                metadata=trace_metadata,
            )
        )
    response = ActionGuardResponse(
        replay_id=request.replay_id,
        session_id=session_id,
        agent=request.agent,
        surface=request.surface,
        allowed=execution.decision.allowed,
        mode=execution.decision.mode,
        reason=execution.decision.reason,
        tool_name=execution.tool_name,
        risk_score=execution.risk_score,
        sanitized_args=execution.decision.sanitized_args,
        observation=execution.observation,
        latency_ms=execution.latency_ms,
        risk_findings=execution.risk_findings,
        policy_decision=execution.policy_decision,
        defense_actions=defense_actions,
        execution_report=execution.execution_report,
        lifecycle_report=execution.lifecycle_report,
    )
    decision_record = build_decision_record(
        envelope=runtime_envelope,
        stage="executor",
        risk_findings=execution.risk_findings,
        policy_decision=execution.policy_decision,
        trace_events=trace_events,
        execution_plan=execution.execution_plan,
        execution_report=execution.execution_report,
        lifecycle_report=execution.lifecycle_report,
    )
    return ActionDecisionFlowResult(response=response, execution=execution, trace_events=trace_events, decision_record=decision_record)


def run_action_observation_flow(request: ActionObservationRequest) -> ActionObservationFlowResult:
    started = perf_counter()
    analysis = output_guard.analyze(request.observation)
    latency_ms = round((perf_counter() - started) * 1000.0, 3)
    trace_metadata = action_observation_trace_metadata(
        metadata=request.metadata,
        replay_id=request.replay_id,
        agent=request.agent,
        surface=request.surface,
    )
    runtime_envelope = action_observation_envelope(request=request, trace_metadata=trace_metadata)
    observation_policy = observe_output_analysis(
        surface=request.surface,
        output_analysis=analysis,
        session_id=request.session_id,
        event_type="action_guard_observation",
        metadata=trace_metadata,
        output_threshold=None,
        fallback_trace_id=request.replay_id or request.session_id,
        latency_ms=latency_ms,
    )
    sanitized_observation = request.observation
    if not observation_policy.safe_to_return:
        sanitized_observation = safe_observation_text(request.observation)
    defense_actions = build_defense_actions(
        flow="observation",
        policy_decision=observation_policy.policy_decision,
        risk_findings=observation_policy.risk_findings,
        trust_boundary="untrusted_tool_observation",
        explicit_attack_vector=str(request.metadata.get("attack_vector", "")),
    )
    if defense_actions:
        observation_policy.trace_events.append(
            defense_trace_event(
                trace_id=trace_id_from_metadata(trace_metadata, fallback=request.replay_id or request.session_id),
                payload_ref=f"{request.session_id}:action_guard_observation",
                defense_actions=defense_actions,
                metadata=trace_metadata,
            )
        )
    response = ActionObservationResponse(
        replay_id=request.replay_id,
        session_id=request.session_id,
        agent=request.agent,
        surface=request.surface,
        safe_to_return=observation_policy.safe_to_return,
        mode=observation_policy.mode,
        sanitized_observation=sanitized_observation,
        output_analysis=analysis,
        latency_ms=latency_ms,
        risk_findings=observation_policy.risk_findings,
        policy_decision=observation_policy.policy_decision,
        defense_actions=defense_actions,
    )
    decision_record = build_decision_record(
        envelope=runtime_envelope,
        stage="observation",
        risk_findings=observation_policy.risk_findings,
        policy_decision=observation_policy.policy_decision,
        trace_events=observation_policy.trace_events,
    )
    return ActionObservationFlowResult(response=response, trace_events=observation_policy.trace_events, decision_record=decision_record)
