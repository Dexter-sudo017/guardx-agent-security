from typing import Any

from app.contracts import RiskFinding, RiskSegment
from app.risk_providers.normalization import finding_from_analysis, finding_from_score, findings_from_analyses
from app.risk_providers.segments import canonical_surface


def _authoritative_provider_ids(provider_findings: list[RiskFinding] | None) -> set[str]:
    return {
        finding.provider_id
        for finding in provider_findings or []
        if not any(ref.startswith(("provider_error:", "sidecar_unavailable:")) for ref in finding.evidence_refs)
    }


def guarded_risk_findings(
    *,
    surface: str,
    input_analysis: Any,
    embedding_analysis: Any | None = None,
    context_analysis: Any | None = None,
    output_analysis: Any | None = None,
    segments: list[RiskSegment] | None = None,
    provider_findings: list[RiskFinding] | None = None,
) -> list[RiskFinding]:
    canonical = canonical_surface(surface)
    registered_provider_ids = _authoritative_provider_ids(provider_findings)
    embedding_metadata = dict(getattr(embedding_analysis, "metadata", {}) or {})
    embedding_disabled = bool(embedding_metadata.get("embedding_disabled"))
    qwen3_present = any(
        key in embedding_metadata
        for key in ("qwen3_joint_online", "qwen3_external_calibration", "qwen3_joint_online_error")
    )
    effective_embedding_analysis = None if embedding_disabled and not qwen3_present else embedding_analysis
    embedding_provider_id = "qwen3_online_embedguard" if embedding_disabled and qwen3_present else "srtp_embedguard"
    findings = findings_from_analyses(
        ("input_guard", canonical, input_analysis, "jailbreak"),
        ("context_guard", canonical, context_analysis, "prompt_injection"),
        (embedding_provider_id, canonical, effective_embedding_analysis, "prompt_injection"),
        ("output_guard", canonical, output_analysis, "unsafe_content"),
    )
    if registered_provider_ids:
        findings = [finding for finding in findings if finding.provider_id not in registered_provider_ids]
        findings.extend(provider_findings or [])
    if segments:
        segment_features = [segment.model_dump() for segment in segments]
        for finding in findings:
            finding.features["segments"] = segment_features
    return findings


def action_guard_risk_finding(
    *,
    surface: str,
    tool_name: str,
    risk_score: float,
    decision: Any,
    latency_ms: float = 0.0,
) -> RiskFinding:
    return finding_from_score(
        provider_id="action_guard",
        surface=canonical_surface(surface),
        risk_score=float(risk_score),
        risk_type="tool_abuse",
        evidence_refs=list(getattr(decision, "evidence", []) or [str(getattr(decision, "reason", ""))]),
        features={
            "tool_name": tool_name,
            "mode": getattr(decision, "mode", ""),
            "allowed": getattr(decision, "allowed", None),
            "sanitized_args": getattr(decision, "sanitized_args", {}),
            "rule_id": getattr(decision, "rule_id", ""),
            "constraints": getattr(decision, "constraints", {}),
        },
        latency_ms=latency_ms,
    )


def observation_risk_finding(*, surface: str, analysis: Any, latency_ms: float = 0.0) -> RiskFinding:
    return finding_from_analysis(
        "output_guard",
        canonical_surface(surface),
        analysis,
        risk_type="privacy_leakage",
        latency_ms=latency_ms,
    )
