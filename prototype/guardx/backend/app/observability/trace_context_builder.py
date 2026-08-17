from typing import Any


def _metadata_dict(metadata: dict[str, Any] | None) -> dict[str, Any]:
    return dict(metadata) if isinstance(metadata, dict) else {}


def _with_defaults(metadata: dict[str, Any] | None, **defaults: Any) -> dict[str, Any]:
    result = {key: value for key, value in defaults.items() if value is not None}
    result.update(_metadata_dict(metadata))
    return result


def _with_overrides(metadata: dict[str, Any] | None, **overrides: Any) -> dict[str, Any]:
    result = _metadata_dict(metadata)
    result.update({key: value for key, value in overrides.items() if value is not None})
    return result


def action_decision_trace_metadata(
    *,
    task_context: dict[str, Any] | None,
    replay_id: str,
    agent: str,
    surface: str,
    execution_key: str,
) -> dict[str, Any]:
    return _with_overrides(
        task_context,
        replay_id=replay_id,
        agent=agent,
        surface=surface,
        execution_key=execution_key,
    )


def action_observation_trace_metadata(
    *,
    metadata: dict[str, Any] | None,
    replay_id: str,
    agent: str,
    surface: str,
) -> dict[str, Any]:
    return _with_overrides(
        metadata,
        replay_id=replay_id,
        agent=agent,
        surface=surface,
    )


def guarded_trace_metadata(*, metadata: dict[str, Any] | None, surface: str) -> dict[str, Any]:
    return _with_defaults(metadata, surface=surface)


def tool_execution_trace_metadata(
    *,
    metadata: dict[str, Any] | None = None,
    surface: str = "agent_tool",
    execution_key: str | None = None,
) -> dict[str, Any]:
    return _with_overrides(metadata, surface=surface, execution_key=execution_key)


def proxy_trace_metadata(
    *,
    metadata: dict[str, Any] | None,
    replay_id: str,
    surface: str,
    workspace_slug: str | None = None,
) -> dict[str, Any]:
    return _with_defaults(
        metadata,
        replay_id=replay_id,
        workspace_slug=workspace_slug,
        surface=surface,
    )
