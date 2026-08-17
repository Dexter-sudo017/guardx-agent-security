from __future__ import annotations

import pytest

from app.compat.authorization_vocabulary import (
    AuthorizationVocabularyError,
    CANONICAL_TO_R4A,
    R4A_TO_CANONICAL,
    canonical_to_r4a,
    r4a_to_canonical,
)
from app.continuation import DefaultContinuationHook
from app.contracts import AuthorizationContext, AuthorizationFinding


def _context(**updates) -> AuthorizationContext:
    values = {
        "context_id": "compat-test",
        "user_goal": "complete the original task",
        "source": "authenticated_user",
        "source_trust": "trusted",
        "requested_capability": "file_write",
        "action_origin": "runtime_planned",
    }
    values.update(updates)
    return AuthorizationContext(**values)


def _finding(decision: str, **updates) -> AuthorizationFinding:
    values = {
        "source_authority": "authorized_instruction",
        "task_alignment": True,
        "action_alignment": True,
        "requested_capability": "file_write",
        "capability_granted": True,
        "data_flow": "authorized_local",
        "decision": decision,
    }
    values.update(updates)
    return AuthorizationFinding(**values)


def test_vocabulary_mapping_is_exhaustive_and_deterministic() -> None:
    assert set(CANONICAL_TO_R4A) == {
        "ALLOW",
        "ALLOW_WITH_CONSTRAINTS",
        "QUARANTINE_AND_CONTINUE",
        "REQUIRE_APPROVAL",
        "DENY_ACTION",
        "TERMINATE",
    }
    for frozen, canonical in R4A_TO_CANONICAL.items():
        assert r4a_to_canonical(frozen) == canonical
        assert r4a_to_canonical(frozen) == canonical
    for canonical, frozen in CANONICAL_TO_R4A.items():
        assert canonical_to_r4a(canonical) == frozen


def test_unknown_values_fail_closed() -> None:
    with pytest.raises(AuthorizationVocabularyError):
        r4a_to_canonical("model_invented_allow")
    with pytest.raises(AuthorizationVocabularyError):
        canonical_to_r4a("ALLOW_ANYTHING")


@pytest.mark.parametrize(
    ("decision", "origin", "approval_state", "expected"),
    [
        ("ALLOW", "runtime_planned", "not_required", "CONTINUE"),
        ("ALLOW", "user_goal", "not_required", "COMPLETED"),
        ("ALLOW_WITH_CONSTRAINTS", "runtime_planned", "not_required", "CONTINUE"),
        ("QUARANTINE_AND_CONTINUE", "observation", "not_required", "QUARANTINE_AND_CONTINUE"),
        ("DENY_ACTION", "observation", "not_required", "QUARANTINE_AND_CONTINUE"),
        ("DENY_ACTION", "user_goal", "not_required", "TERMINATE"),
        ("REQUIRE_APPROVAL", "user_goal", "pending", "PAUSE_FOR_APPROVAL"),
        ("REQUIRE_APPROVAL", "runtime_planned", "approved", "CONTINUE"),
        ("REQUIRE_APPROVAL", "user_goal", "approved", "COMPLETED"),
        ("TERMINATE", "runtime_planned", "not_required", "TERMINATE"),
    ],
)
def test_production_hook_preserves_r4a_control_flow(
    decision: str,
    origin: str,
    approval_state: str,
    expected: str,
) -> None:
    context = _context(action_origin=origin, approval_state=approval_state)
    plan = DefaultContinuationHook().plan(context, _finding(decision))
    assert plan.control_flow == expected
