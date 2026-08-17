from typing import Any

from app.contracts import PolicyDecision, RiskFinding
from app.policy import decide_policy_from_score, legacy_action_from_policy_decision, override_policy_decision


def policy_decision_for_findings(total_risk: float, risk_findings: list[RiskFinding], *, thresholds: Any | None = None) -> PolicyDecision:
    reasons = sorted({ref for finding in risk_findings for ref in finding.evidence_refs if ref})
    required_guards = sorted({finding.provider_id for finding in risk_findings})
    return decide_policy_from_score(total_risk, reasons=reasons, required_guards=required_guards, thresholds=thresholds)


def legacy_action_for_policy(decision: PolicyDecision) -> str:
    return legacy_action_from_policy_decision(decision)


def output_override_policy_decision(decision: PolicyDecision, output_finding: RiskFinding, *, threshold: float) -> PolicyDecision:
    if output_finding.risk_score < threshold:
        return decision
    return override_policy_decision(
        decision,
        route="review",
        action="redact",
        reasons=[*output_finding.evidence_refs, "output_guard_threshold"],
        required_guards=[output_finding.provider_id],
        audit_level="full",
        risk_score=max(decision.risk_score, output_finding.risk_score),
    )


def denied_action_policy_decision(decision: PolicyDecision, action_finding: RiskFinding) -> PolicyDecision:
    return override_policy_decision(
        decision,
        route="block",
        action="terminate",
        reasons=[*action_finding.evidence_refs, "action_guard_denied"],
        required_guards=[action_finding.provider_id],
        audit_level="full",
        risk_score=max(decision.risk_score, action_finding.risk_score),
    )
