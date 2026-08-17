from typing import Any

from app.config import SETTINGS
from app.guards import embedding_guard_online
from app.models import AnalysisResult, GuardedVlmOcrRequest
from app.policy.engine import merge_risk


def merge_risk_with_embedding_route(
    input_analysis: AnalysisResult,
    context_analysis: AnalysisResult | None,
    session_risk: float,
    embedding_analysis: AnalysisResult | None,
    surface: str,
) -> float:
    raw_risk = merge_risk(input_analysis, context_analysis, session_risk, embedding_analysis)
    if embedding_analysis is None:
        return raw_risk
    external = dict(embedding_analysis.metadata.get("qwen3_external_calibration", {}))
    if external.get("route") != "allow":
        return raw_risk
    try:
        policy = embedding_guard_online.load_online_policy()
    except Exception:
        return raw_risk
    config = dict(dict(policy.get("external_calibration", {})).get("route_allow_merge_recovery", {}))
    if not config.get("enabled", False):
        return raw_risk
    surfaces = {str(item) for item in config.get("surfaces", ["rag", "vlm_ocr"])}
    if surface not in surfaces:
        return raw_risk
    segment_route_allow = dict(external.get("segment_safe_frame_route_allow", {}))
    learned = external.get("learned_safe_frame_adapter")
    if isinstance(learned, dict) and learned.get("enabled") and learned.get("is_risky") and not segment_route_allow.get("applied"):
        embedding_analysis.metadata["guardx_route_allow_merge_recovery"] = {
            "enabled": True,
            "applied": False,
            "reason": "learned_adapter_risky",
            "surface": surface,
            "raw_risk": round(raw_risk, 6),
            "learned_safe_frame_adapter": learned,
        }
        return raw_risk
    max_embedding_risk = float(config.get("max_embedding_risk", 0.2))
    if float(embedding_analysis.risk_score) > max_embedding_risk:
        return raw_risk
    blocked_labels = {str(item) for item in config.get("blocked_labels", [])}
    recoverable_blocked_labels = {str(item) for item in config.get("recoverable_blocked_labels", [])}
    labels = set(input_analysis.labels)
    if context_analysis is not None:
        labels.update(context_analysis.labels)
    blocked_hits = blocked_labels.intersection(labels)
    hard_blocked_hits = blocked_hits - recoverable_blocked_labels
    recoverable_hits = blocked_hits.intersection(recoverable_blocked_labels)
    if recoverable_hits and "benign_safety_context" not in labels:
        hard_blocked_hits.update(recoverable_hits)
    if hard_blocked_hits and not segment_route_allow.get("applied"):
        embedding_analysis.metadata["guardx_route_allow_merge_recovery"] = {
            "enabled": True,
            "applied": False,
            "reason": "blocked_guard_label",
            "blocked_labels": sorted(hard_blocked_hits),
            "raw_risk": round(raw_risk, 6),
        }
        return raw_risk
    cap = float(config.get("risk_cap", SETTINGS.thresholds.medium - 0.01))
    recovered = min(raw_risk, cap)
    embedding_analysis.metadata["guardx_route_allow_merge_recovery"] = {
        "enabled": True,
        "applied": recovered < raw_risk,
        "reason": "embedding_route_allow_low_risk",
        "surface": surface,
        "raw_risk": round(raw_risk, 6),
        "recovered_risk": round(recovered, 6),
        "embedding_risk": round(float(embedding_analysis.risk_score), 6),
        "route": external.get("route"),
        "recoverable_blocked_labels": sorted(recoverable_hits),
        "ignored_blocked_labels": sorted(hard_blocked_hits) if segment_route_allow.get("applied") else [],
        "segment_safe_frame_route_allow": segment_route_allow if segment_route_allow.get("applied") else None,
    }
    return recovered


def recover_benign_vlm_visual_training(
    *,
    request: GuardedVlmOcrRequest,
    visual_signals: Any,
    visual_caption: Any,
    total_risk: float,
    embedding_analysis: AnalysisResult,
) -> float:
    if not isinstance(visual_signals, list) or visual_signals:
        return total_risk
    text = "\n".join(
        str(item)
        for item in [
            request.message,
            request.ocr_text,
            request.vlm_answer or "",
            visual_caption if isinstance(visual_caption, str) else "",
        ]
    ).lower()
    safe_cues = {
        "awareness",
        "training",
        "benign",
        "recognize",
        "recognizing",
        "suspicious verification",
        "safe handling",
        "privacy",
        "redact",
        "redaction",
        "sanitize",
        "sanitization",
        "安全",
        "隐私",
        "脱敏",
        "审计",
    }
    hard_visual_risk_cues = {
        "credential collection",
        "credential entry",
        "capture path",
        "external capture",
        "source priority",
        "override",
        "reveal",
        "exfiltrate",
    }
    if not any(cue in text for cue in safe_cues):
        return total_risk
    if any(cue in text for cue in hard_visual_risk_cues):
        return total_risk
    recovered = min(total_risk, SETTINGS.thresholds.medium - 0.02)
    if recovered < total_risk:
        embedding_analysis.metadata["guardx_vlm_visual_safe_training_recovery"] = {
            "applied": True,
            "reason": "benign_visual_training_without_active_visual_risk_signals",
            "raw_risk": round(total_risk, 6),
            "recovered_risk": round(recovered, 6),
        }
    return recovered


__all__ = [
    "merge_risk_with_embedding_route",
    "recover_benign_vlm_visual_training",
]
