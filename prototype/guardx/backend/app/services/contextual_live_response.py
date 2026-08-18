from typing import Any

from fastapi import HTTPException, Request


_ENFORCEMENT_ORDER = {"ALLOW": 0, "ALLOW_WITH_CONSTRAINTS": 1, "REQUIRE_APPROVAL": 2, "QUARANTINE_AND_CONTINUE": 3, "DENY_ACTION": 4, "TERMINATE": 5}


def evaluate_context(raw_request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    manager = getattr(raw_request.app.state, "nf_portal_manager", None)
    service = getattr(manager, "service", None)
    if service is None:
        raise HTTPException(status_code=503, detail="Contextual Authorization runtime is unavailable")
    try:
        return service.evaluate_context(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def strongest_result(results: list[dict[str, Any]]) -> dict[str, Any] | None:
    restricted = [item for item in results if item["policy_decision"]["enforcement"] not in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}]
    return max(restricted, key=lambda item: _ENFORCEMENT_ORDER[item["policy_decision"]["enforcement"]]) if restricted else None


def blocked_response(*, session_id: str, strongest: dict[str, Any], evaluations: list[dict[str, Any]], extra: dict[str, Any]) -> dict[str, Any]:
    decision = strongest["policy_decision"]
    finding = strongest["model_finding"]
    evidence_ids = [item["evidence_replay_verify"]["record_hash"] for item in evaluations]
    return {
        "session_id": session_id,
        "model": strongest["provider"].get("model") or "task-relation-judge",
        "action": decision["action"],
        "answer": "GuardX 已隔离非可信内容中的控制指令；下游业务模型未被调用，原始任务可在保留事实内容后继续。",
        "risk_score": decision["risk_score"],
        "input_analysis": {"risk_score": decision["risk_score"], "labels": ["contextual_authorization"], "evidence": evidence_ids, "metadata": {}},
        "context_analysis": {"risk_score": decision["risk_score"], "labels": [finding["decision"]], "evidence": evidence_ids, "metadata": {}},
        "risk_findings": [
            {"risk_type": "task_relation_conflict", "risk_score": item["policy_decision"]["risk_score"], "severity": "high" if item["policy_decision"]["risk_score"] >= 0.7 else "medium", "evidence": [item["model_finding"]["evidence"].get("task_relation", {})], "metadata": {"run_id": item["run_id"], "surface": item["surface"]}}
            for item in evaluations if item["policy_decision"]["enforcement"] not in {"ALLOW", "ALLOW_WITH_CONSTRAINTS"}
        ],
        "policy_decision": decision,
        "defense_actions": [{"method": "contextual_quarantine", "runtime_action": decision["enforcement"]}],
        "model_invoked": False,
        "relation_model_invoked": any(bool(item.get("model_called")) for item in evaluations),
        "response_source": "guardx_contextual_policy_v2",
        "contextual_evaluations": evaluations,
        "evidence_ids": evidence_ids,
        **extra,
    }
