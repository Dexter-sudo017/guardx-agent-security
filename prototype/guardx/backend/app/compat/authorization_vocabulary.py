from __future__ import annotations

from typing import Final


class AuthorizationVocabularyError(ValueError):
    """Raised when a frozen/canonical decision cannot be mapped safely."""


R4A_TO_CANONICAL: Final[dict[str, str]] = {
    "allow": "ALLOW",
    "allow_with_constraints": "ALLOW_WITH_CONSTRAINTS",
    "quarantine_instruction": "QUARANTINE_AND_CONTINUE",
    "quarantine_and_continue": "QUARANTINE_AND_CONTINUE",
    "require_approval": "REQUIRE_APPROVAL",
    "review": "REQUIRE_APPROVAL",
    "deny_action": "DENY_ACTION",
    "terminate": "TERMINATE",
}

CANONICAL_TO_R4A: Final[dict[str, str]] = {
    "ALLOW": "allow",
    # R4-A has no distinct constrained-allow authorization value; constraints
    # remain in the verified Core-v2 finding while continuation sees allow.
    "ALLOW_WITH_CONSTRAINTS": "allow",
    "QUARANTINE_AND_CONTINUE": "quarantine_and_continue",
    "REQUIRE_APPROVAL": "require_approval",
    "DENY_ACTION": "deny_action",
    "TERMINATE": "terminate",
}


def r4a_to_canonical(value: str) -> str:
    if value in CANONICAL_TO_R4A:
        return value
    try:
        return R4A_TO_CANONICAL[value]
    except (KeyError, TypeError) as exc:
        raise AuthorizationVocabularyError(f"unknown R4-A authorization decision: {value!r}") from exc


def canonical_to_r4a(value: str) -> str:
    try:
        return CANONICAL_TO_R4A[value]
    except (KeyError, TypeError) as exc:
        raise AuthorizationVocabularyError(f"unknown canonical authorization decision: {value!r}") from exc
