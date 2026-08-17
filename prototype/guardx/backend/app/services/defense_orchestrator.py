from __future__ import annotations

from typing import Any

from app.contracts import PolicyDecision, RiskFinding
from app.services.defense_playbook import recommend_defense


BENIGN_RECOVERY_VECTORS = {
    "benign_roleplay",
    "benign_training_quote",
    "benign_ocr_privacy_training",
    "benign_tool_use",
    "benign_plugin_manifest_review",
    "benign_security_operations",
}


def _attack_vector_for_finding(*, flow: str, finding: RiskFinding) -> str:
    provider = finding.provider_id
    risk_type = str(finding.risk_type)
    surface = str(finding.surface)
    features = finding.features or {}
    rule_id = str(features.get("rule_id") or features.get("policy_rule") or "")

    if provider == "output_guard" or flow in {"observation", "tool_observation"}:
        return "tool_output_injection"
    if flow == "rag" or surface == "rag":
        return "indirect_prompt_injection"
    if flow in {"vlm", "vlm_ocr"} or surface == "vlm":
        return "ocr_hidden_instruction"
    if provider == "action_guard" or risk_type == "tool_abuse":
        if "network" in rule_id or "domain" in rule_id or "url" in rule_id:
            return "network_exfiltration"
        if "file" in rule_id or "path" in rule_id or "secret" in rule_id or "credential" in rule_id:
            return "sensitive_file_read"
        return "network_exfiltration" if "network" in str(features).lower() else "sensitive_file_read"
    if risk_type == "prompt_injection":
        return "indirect_prompt_injection" if flow in {"rag", "vlm_ocr"} else "euphemistic_policy_override"
    if risk_type == "privacy_leakage":
        return "sensitive_file_read"
    return "roleplay_policy_bypass" if flow == "chat" else "policy.default_review"


def _execution_action_vector(execution_report: Any | None, policy_decision: PolicyDecision | None) -> str:
    if execution_report is None:
        return ""
    dumped = execution_report.model_dump() if hasattr(execution_report, "model_dump") else dict(execution_report or {})
    text = str(dumped).lower()
    if any(marker in text for marker in ("network", "domain", "url", "http", "https")):
        return "network_exfiltration"
    if any(marker in text for marker in ("file", "path", ".env", "token", "secret", "credential")):
        return "sensitive_file_read"
    if policy_decision and policy_decision.route != "allow":
        return "sensitive_file_read"
    return ""


def build_defense_actions(
    *,
    flow: str,
    policy_decision: PolicyDecision | None,
    risk_findings: list[RiskFinding],
    trust_boundary: str = "",
    execution_report: Any | None = None,
    explicit_attack_vector: str = "",
) -> list[dict[str, Any]]:
    route = policy_decision.route if policy_decision else "allow"
    provider_ids = [finding.provider_id for finding in risk_findings]
    vectors: list[str] = []
    explicit_vector = explicit_attack_vector.strip()
    if explicit_vector in BENIGN_RECOVERY_VECTORS:
        vectors.append(explicit_vector)
    elif explicit_vector:
        vectors.append(explicit_attack_vector)
        vectors.extend(_attack_vector_for_finding(flow=flow, finding=finding) for finding in risk_findings if finding.risk_score > 0)
        execution_vector = _execution_action_vector(execution_report, policy_decision)
        if execution_vector:
            vectors.append(execution_vector)
    else:
        vectors.extend(_attack_vector_for_finding(flow=flow, finding=finding) for finding in risk_findings if finding.risk_score > 0)
        execution_vector = _execution_action_vector(execution_report, policy_decision)
        if execution_vector:
            vectors.append(execution_vector)
    if not vectors and policy_decision and policy_decision.route == "allow":
        vectors.append("benign_tool_use" if flow in {"action", "tool"} else "benign_roleplay")

    actions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for vector in vectors:
        playbook = recommend_defense(
            attack_vector=vector,
            trust_boundary=trust_boundary,
            route=route,
            risk_provider_ids=provider_ids,
        )
        defense_id = str(playbook.get("defense_id", ""))
        if defense_id in seen:
            continue
        seen.add(defense_id)
        actions.append(
            {
                "defense_id": defense_id,
                "method": playbook.get("method"),
                "runtime_action": playbook.get("runtime_action"),
                "controls": playbook.get("controls", []),
                "route": route,
                "attack_vector": playbook.get("attack_vector"),
                "trust_boundary": playbook.get("trust_boundary"),
                "is_detection_only": False,
            }
        )
    return actions


def defense_trace_event(*, trace_id: str, payload_ref: str, defense_actions: list[dict[str, Any]], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "event_type": "defense_orchestration",
        "stage": "policy",
        "trace_id": trace_id,
        "span_id": f"{trace_id}:defense",
        "payload_ref": payload_ref,
        "risk_snapshot": {
            "defense_actions": defense_actions,
            "defense_count": len(defense_actions),
            "metadata": metadata or {},
        },
    }


__all__ = ["build_defense_actions", "defense_trace_event"]
