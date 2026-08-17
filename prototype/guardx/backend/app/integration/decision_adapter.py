from __future__ import annotations

from dataclasses import dataclass

from app.contracts.executor_integration import CORE_V2_COMPATIBILITY_VERSION, CanonicalDecision


@dataclass(frozen=True)
class DecisionDisposition:
    canonical: CanonicalDecision
    execute: bool
    approval_required: bool
    continue_task: bool
    terminate: bool
    constrained: bool


_ALIASES: dict[str, CanonicalDecision] = {
    "ALLOW": "ALLOW",
    "allow": "ALLOW",
    "ALLOW_WITH_CONSTRAINTS": "ALLOW_WITH_CONSTRAINTS",
    "allow_with_constraints": "ALLOW_WITH_CONSTRAINTS",
    "QUARANTINE_AND_CONTINUE": "QUARANTINE_AND_CONTINUE",
    "quarantine_and_continue": "QUARANTINE_AND_CONTINUE",
    "quarantine_instruction": "QUARANTINE_AND_CONTINUE",
    "REQUIRE_APPROVAL": "REQUIRE_APPROVAL",
    "require_approval": "REQUIRE_APPROVAL",
    "review": "REQUIRE_APPROVAL",
    "DENY_ACTION": "DENY_ACTION",
    "deny_action": "DENY_ACTION",
    "TERMINATE": "TERMINATE",
    "terminate": "TERMINATE",
}

_DISPOSITIONS: dict[CanonicalDecision, DecisionDisposition] = {
    "ALLOW": DecisionDisposition("ALLOW", True, False, True, False, False),
    "ALLOW_WITH_CONSTRAINTS": DecisionDisposition("ALLOW_WITH_CONSTRAINTS", True, False, True, False, True),
    "QUARANTINE_AND_CONTINUE": DecisionDisposition("QUARANTINE_AND_CONTINUE", False, False, True, False, False),
    "REQUIRE_APPROVAL": DecisionDisposition("REQUIRE_APPROVAL", False, True, False, False, False),
    "DENY_ACTION": DecisionDisposition("DENY_ACTION", False, False, True, False, False),
    "TERMINATE": DecisionDisposition("TERMINATE", False, False, False, True, False),
}


def map_core_decision(value: str) -> DecisionDisposition:
    try:
        canonical = _ALIASES[value.strip()]
    except KeyError as exc:
        raise ValueError(f"unsupported authorization decision for {CORE_V2_COMPATIBILITY_VERSION}: {value}") from exc
    return _DISPOSITIONS[canonical]


def compatibility_matrix() -> list[dict[str, object]]:
    descriptions = {
        "ALLOW": "execute",
        "ALLOW_WITH_CONSTRAINTS": "validate frozen constraints, then execute",
        "QUARANTINE_AND_CONTINUE": "skip malicious action and continue task",
        "REQUIRE_APPROVAL": "pause without side effect",
        "DENY_ACTION": "skip without side effect",
        "TERMINATE": "terminate lifecycle without execution",
    }
    return [
        {
            "source_decision": name,
            "canonical_decision": disposition.canonical,
            "effect": descriptions[name],
            "execute": disposition.execute,
            "approval_required": disposition.approval_required,
            "continue_task": disposition.continue_task,
            "terminate": disposition.terminate,
        }
        for name, disposition in _DISPOSITIONS.items()
    ]
