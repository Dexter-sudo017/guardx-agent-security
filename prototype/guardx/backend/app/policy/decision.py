from typing import Any

from app.config import SETTINGS
from app.contracts import PolicyDecision, RiskFinding


def aggregate_risk_findings(findings: list[RiskFinding]) -> float:
    if not findings:
        return 0.0
    return min(1.0, max(float(item.risk_score) for item in findings))


def _thresholds(thresholds: Any | None = None) -> Any:
    return thresholds or SETTINGS.thresholds


def decide_policy_from_score(
    risk_score: float,
    *,
    reasons: list[str] | None = None,
    required_guards: list[str] | None = None,
    thresholds: Any | None = None,
) -> PolicyDecision:
    score = min(1.0, max(0.0, float(risk_score)))
    active_thresholds = _thresholds(thresholds)
    if score >= active_thresholds.critical:
        return PolicyDecision(
            route="block",
            action="terminate",
            risk_score=score,
            reasons=reasons or ["critical_risk_threshold"],
            required_guards=required_guards or [],
            audit_level="full",
        )
    if score >= active_thresholds.high:
        return PolicyDecision(
            route="block",
            action="terminate",
            risk_score=score,
            reasons=reasons or ["high_risk_threshold"],
            required_guards=required_guards or [],
            audit_level="full",
        )
    if score >= active_thresholds.medium:
        return PolicyDecision(
            route="review",
            action="rewrite",
            risk_score=score,
            reasons=reasons or ["medium_risk_threshold"],
            required_guards=required_guards or [],
            audit_level="full",
        )
    return PolicyDecision(
        route="allow",
        action="allow",
        risk_score=score,
        reasons=reasons or ["below_medium_risk_threshold"],
        required_guards=required_guards or [],
        audit_level="summary",
    )


def decide_policy_from_findings(findings: list[RiskFinding], *, thresholds: Any | None = None) -> PolicyDecision:
    score = aggregate_risk_findings(findings)
    reasons = sorted({evidence for finding in findings for evidence in finding.evidence_refs})
    required_guards = sorted({finding.provider_id for finding in findings})
    return decide_policy_from_score(score, reasons=reasons, required_guards=required_guards, thresholds=thresholds)


def legacy_action_from_policy_decision(decision: PolicyDecision) -> str:
    if decision.action == "redact":
        return "redact_output"
    if decision.action == "require_confirm":
        return "rewrite"
    return decision.action


def override_policy_decision(
    decision: PolicyDecision,
    *,
    route: str | None = None,
    action: str | None = None,
    reasons: list[str] | None = None,
    constraints: dict | None = None,
    required_guards: list[str] | None = None,
    audit_level: str | None = None,
    risk_score: float | None = None,
) -> PolicyDecision:
    merged_reasons = list(dict.fromkeys([*decision.reasons, *(reasons or [])]))
    merged_required_guards = list(dict.fromkeys([*decision.required_guards, *(required_guards or [])]))
    merged_constraints = {**decision.constraints, **(constraints or {})}
    return PolicyDecision(
        route=route or decision.route,
        action=action or decision.action,
        risk_score=decision.risk_score if risk_score is None else min(1.0, max(0.0, float(risk_score))),
        reasons=merged_reasons,
        constraints=merged_constraints,
        required_guards=merged_required_guards,
        audit_level=audit_level or decision.audit_level,
    )
