from __future__ import annotations

from typing import Any


_CONTEXT_METADATA_KEYS = (
    "case_id",
    "family",
    "phase",
    "expected_defense_action",
    "attack_vector",
    "trust_boundary",
)


def attach_guardx_context(args: dict[str, Any], context: dict[str, Any] | None) -> dict[str, Any]:
    prepared = dict(args)
    if not context:
        return prepared
    for key in _CONTEXT_METADATA_KEYS:
        value = context.get(key)
        if value is not None:
            prepared[f"_guardx_{key}"] = value
    return prepared
