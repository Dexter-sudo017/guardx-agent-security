from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from app.capabilities import CapabilityStore
from app.contracts import AuthorizationFinding, ContextualAuthorizationRequest, PolicyV2Result
from app.policy.authorization_v2 import decide_contextual_authorization
from app.policy.decision import decide_policy_from_score


PolicyMode = Literal["legacy", "contextual_v2"]
PROJECT_ROOT = Path(__file__).resolve().parents[5]
AUTHORIZATION_CONFIG_PATH = PROJECT_ROOT / "configs" / "authorization_runtime.json"


@lru_cache(maxsize=1)
def configured_policy_mode() -> PolicyMode:
    configured = "contextual_v2"
    if AUTHORIZATION_CONFIG_PATH.exists():
        payload = json.loads(AUTHORIZATION_CONFIG_PATH.read_text(encoding="utf-8"))
        configured = str(payload.get("mode") or configured)
    value = os.getenv("GUARDX_AUTHORIZATION_MODE", configured)
    if value not in {"legacy", "contextual_v2"}:
        raise ValueError(f"unsupported GuardX authorization mode: {value}")
    return value  # type: ignore[return-value]


def _legacy_result(request: ContextualAuthorizationRequest) -> PolicyV2Result:
    decision = decide_policy_from_score(request.legacy_risk_score)
    if decision.route == "allow":
        enforcement = "ALLOW"
    elif decision.route == "review":
        enforcement = "REQUIRE_APPROVAL"
    else:
        enforcement = "TERMINATE"
    finding = AuthorizationFinding(
        provider_id="legacy_max_risk_threshold",
        source_authority="unknown",
        task_alignment=True,
        action_alignment=True,
        requested_capability=request.requested_capability,
        capability_granted=False,
        data_flow="legacy_not_evaluated",
        matched_rules=[],
        decision=enforcement,
        preserve_observation=True,
        continue_original_task=decision.route != "block",
        confidence=1.0,
        model_version="legacy_max_risk_threshold",
        evidence={"legacy_risk_score": request.legacy_risk_score, "capability_verification_applied": False},
    )
    return PolicyV2Result(
        mode="legacy",
        finding=finding,
        policy_decision=decision,
        enforcement=enforcement,
        legacy_policy_unchanged=True,
        review_required=decision.route == "review",
        continuation={"eligible": False, "hook_invoked": False, "legacy_mode": True},
    )


def evaluate_authorization(
    request: ContextualAuthorizationRequest,
    *,
    mode: PolicyMode | None = None,
    capability_store: CapabilityStore | None = None,
    model_finding: AuthorizationFinding | None = None,
) -> PolicyV2Result:
    active_mode = mode or configured_policy_mode()
    if active_mode == "legacy":
        return _legacy_result(request)
    if active_mode != "contextual_v2":
        raise ValueError(f"unsupported GuardX authorization mode: {active_mode}")
    return decide_contextual_authorization(
        request,
        capability_store=capability_store,
        model_finding=model_finding,
    )
