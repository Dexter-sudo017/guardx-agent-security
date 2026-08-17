from typing import Any

from app.contracts import RiskFinding


def severity_from_score(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.7:
        return "high"
    if score >= 0.45:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _risk_type_from_labels(provider_id: str, labels: list[str], surface: str, fallback: str | None) -> str:
    joined = " ".join(labels).lower()
    if fallback:
        return fallback
    if "privacy" in joined or "credential" in joined or "secret" in joined or provider_id == "output_guard":
        return "privacy_leakage" if any(item in joined for item in ("privacy", "credential", "secret", "leak")) else "unsafe_content"
    if "tool" in joined or surface == "agent_tool" or provider_id == "action_guard":
        return "tool_abuse"
    if "injection" in joined or surface in {"rag", "vlm"}:
        return "prompt_injection"
    if "unsafe" in joined:
        return "unsafe_content"
    return "jailbreak"


def finding_from_score(
    *,
    provider_id: str,
    surface: str,
    risk_score: float,
    risk_type: str,
    confidence: float | None = None,
    evidence_refs: list[str] | None = None,
    features: dict[str, Any] | None = None,
    latency_ms: float = 0.0,
    model_version: str = "unknown",
) -> RiskFinding:
    normalized_score = min(1.0, max(0.0, float(risk_score)))
    return RiskFinding(
        provider_id=provider_id,
        surface=surface,
        risk_score=normalized_score,
        risk_type=risk_type,
        confidence=normalized_score if confidence is None else min(1.0, max(0.0, float(confidence))),
        severity=severity_from_score(normalized_score),
        evidence_refs=list(evidence_refs or []),
        features=dict(features or {}),
        latency_ms=max(0.0, float(latency_ms)),
        model_version=model_version,
    )


def finding_from_analysis(
    provider_id: str,
    surface: str,
    analysis: Any,
    *,
    risk_type: str | None = None,
    latency_ms: float = 0.0,
) -> RiskFinding:
    metadata = dict(getattr(analysis, "metadata", {}) or {})
    labels = [str(item) for item in getattr(analysis, "labels", [])]
    evidence = [str(item) for item in getattr(analysis, "evidence", [])]
    score = float(getattr(analysis, "risk_score", 0.0))
    model_version = str(metadata.get("model_version") or metadata.get("schema_version") or "unknown")
    features = {
        "labels": labels,
        "metadata": metadata,
    }
    return finding_from_score(
        provider_id=provider_id,
        surface=surface,
        risk_score=score,
        risk_type=_risk_type_from_labels(provider_id, labels, surface, risk_type),
        evidence_refs=evidence,
        features=features,
        latency_ms=latency_ms,
        model_version=model_version,
    )


def findings_from_analyses(*items: tuple[str, str, Any] | tuple[str, str, Any, str]) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    for item in items:
        if len(item) == 3:
            provider_id, surface, analysis = item
            risk_type = None
        else:
            provider_id, surface, analysis, risk_type = item
        if analysis is None:
            continue
        findings.append(finding_from_analysis(provider_id, surface, analysis, risk_type=risk_type))
    return findings
