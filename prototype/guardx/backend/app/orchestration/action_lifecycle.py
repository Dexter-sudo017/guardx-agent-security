from app.contracts import GuardedRuntimeEnvelope, RiskSegment, TrustBoundary
from app.models import ActionGuardRequest, ActionObservationRequest
from app.orchestration.lifecycle import build_runtime_envelope


def action_request_envelope(
    *,
    request: ActionGuardRequest,
    execution_key: str,
    trace_metadata: dict,
) -> GuardedRuntimeEnvelope:
    return build_runtime_envelope(
        request_id=request.replay_id or execution_key,
        session_id=request.session_id,
        flow="agent_tool",
        surface=request.surface,
        segments=[
            RiskSegment(
                segment_id=f"agent_tool:action:{request.replay_id or 'live'}",
                text=str(request.action),
                trust_boundary=TrustBoundary(
                    source="agent_action",
                    trust_level="bounded",
                    executable=True,
                    can_instruct_model=False,
                ),
            )
        ],
        metadata=trace_metadata,
    )


def action_observation_envelope(
    *,
    request: ActionObservationRequest,
    trace_metadata: dict,
) -> GuardedRuntimeEnvelope:
    return build_runtime_envelope(
        request_id=request.replay_id or request.session_id,
        session_id=request.session_id,
        flow="agent_tool",
        surface=request.surface,
        segments=[
            RiskSegment(
                segment_id=f"agent_tool:observation:{request.replay_id or 'live'}",
                text=request.observation,
                trust_boundary=TrustBoundary(
                    source="tool_output",
                    trust_level="untrusted",
                    executable=False,
                    can_instruct_model=False,
                ),
            )
        ],
        metadata=trace_metadata,
    )
