from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


def _policy(record: dict[str, Any]) -> dict[str, Any]:
    decision = record.get("decision_record", {}).get("policy_decision", {})
    return decision if isinstance(decision, dict) else {}


def _findings(record: dict[str, Any]) -> list[dict[str, Any]]:
    items = record.get("decision_record", {}).get("risk_findings", [])
    return [item for item in items if isinstance(item, dict)]


def build_security_log_insights(
    audit_store: Any,
    *,
    session_id: str | None = None,
    trace_id: str | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    records = audit_store.decision_records(session_id=session_id, trace_id=trace_id, limit=limit)
    route_counts: Counter[str] = Counter()
    provider_counts: Counter[str] = Counter()
    risk_type_counts: Counter[str] = Counter()
    session_risk: dict[str, dict[str, Any]] = defaultdict(lambda: {"events": 0, "max_risk": 0.0, "blocked": 0, "review": 0})
    findings: list[dict[str, Any]] = []

    for row in records:
        record = row.get("decision_record", {})
        policy = _policy(row)
        route = str(policy.get("route") or "unknown")
        risk_score = float(policy.get("risk_score") or row.get("risk_score") or 0.0)
        sid = str(row.get("session_id") or record.get("envelope", {}).get("session_id") or "unknown")
        route_counts[route] += 1
        bucket = session_risk[sid]
        bucket["events"] += 1
        bucket["max_risk"] = max(float(bucket["max_risk"]), risk_score)
        bucket["blocked"] += int(route == "block")
        bucket["review"] += int(route == "review")
        for finding in _findings(row):
            provider_counts[str(finding.get("provider_id") or "unknown")] += 1
            risk_type_counts[str(finding.get("risk_type") or "unknown")] += 1
        if route in {"block", "review"} or risk_score >= 0.7:
            findings.append(
                {
                    "finding_id": f"log-risk:{record.get('request_id') or len(findings)}",
                    "risk_type": "historical_trace_risk",
                    "severity": "high" if risk_score >= 0.75 or route == "block" else "medium",
                    "session_id": sid,
                    "trace_id": record.get("trace_id"),
                    "route": route,
                    "risk_score": risk_score,
                    "evidence": list(policy.get("reasons") or [])[:5],
                }
            )

    suspicious_sessions = [
        {"session_id": sid, **stats}
        for sid, stats in sorted(session_risk.items(), key=lambda item: (item[1]["blocked"], item[1]["max_risk"]), reverse=True)
        if stats["blocked"] or stats["review"] >= 2 or stats["max_risk"] >= 0.7
    ][:20]
    return {
        "schema_version": "guardx-security-log-insights-v1",
        "absorbed_competition_topics": ["topic6_log_risk_detection", "topic1_llm_agent_security"],
        "scope": {"session_id": session_id, "trace_id": trace_id, "limit": limit},
        "summary": {
            "decision_record_count": len(records),
            "route_counts": dict(route_counts),
            "provider_counts": dict(provider_counts),
            "risk_type_counts": dict(risk_type_counts),
            "finding_count": len(findings),
            "suspicious_session_count": len(suspicious_sessions),
        },
        "findings": findings[:100],
        "suspicious_sessions": suspicious_sessions,
        "recommended_next_actions": [
            "Replay blocked/review traces before changing policy thresholds.",
            "Compare provider counts with model-matrix outcomes to find noisy or missing risk signals.",
            "Promote repeated historical patterns into configured experiment suites.",
        ],
    }
