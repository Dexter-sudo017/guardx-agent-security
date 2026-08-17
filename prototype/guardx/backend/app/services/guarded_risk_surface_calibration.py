from __future__ import annotations

import os
import re
from typing import Any

from app.services.guarded_risk_patterns import (
    EXTERNAL_REVIEW_ACTIVE_RISK_PATTERNS,
    SURFACE_ACTIVE_ATTACK_PATTERNS,
    SURFACE_ATTACK_CONTINUATION_PATTERNS,
    SURFACE_SAFE_CUE_PATTERNS,
    SURFACE_SAFE_OVERRIDES,
    SURFACE_STRONG_SAFE_OVERRIDES,
)


PUBLIC_VLM_OCR_SAFE_PATTERNS = [
    r"公开日程",
    r"校园开放日",
    r"实验室开放日",
    r"公开内容",
    r"无障碍用户",
    r"public schedule",
]


def pattern_hits(patterns: list[str], text: str) -> list[str]:
    return [pattern for pattern in patterns if re.search(pattern, text)]


def surface_calibration_mode(policy: dict[str, Any]) -> str:
    raw = os.environ.get("GUARDX_QWEN3_SURFACE_CALIBRATION_MODE")
    if raw is None or not raw.strip():
        raw = str(dict(policy.get("surface_calibration", {})).get("mode", "full"))
    mode = raw.strip().lower().replace("-", "_")
    aliases = {"off": "no_calibration", "none": "no_calibration", "full_calibration": "full"}
    return aliases.get(mode, mode)


def surface_calibration(text: str, surface: str, policy: dict[str, Any], risk: float, threshold: float) -> tuple[float, dict[str, Any]]:
    config = dict(policy.get("surface_calibration", {}))
    mode = surface_calibration_mode(policy)
    enabled_surfaces = {str(item) for item in config.get("surfaces", [])}
    if mode in {"no_calibration", "threshold_only"}:
        return risk, {"enabled": bool(config.get("enabled", False)), "mode": mode, "applied": False, "reason": mode}
    if not config.get("enabled", False) or surface not in enabled_surfaces:
        return risk, {"enabled": bool(config.get("enabled", False)), "mode": mode, "applied": False, "reason": "not_applicable"}
    lowered = text.lower()
    safe_hits = pattern_hits(SURFACE_SAFE_CUE_PATTERNS, lowered)
    risky_hits = pattern_hits(SURFACE_ACTIVE_ATTACK_PATTERNS, lowered)
    override_hits = pattern_hits(SURFACE_SAFE_OVERRIDES, lowered)
    strong_override_hits = pattern_hits(SURFACE_STRONG_SAFE_OVERRIDES, lowered)
    continuation_hits = pattern_hits(SURFACE_ATTACK_CONTINUATION_PATTERNS, lowered)
    use_safe_frame = mode in {"safe_frame_only", "full"}
    use_active_floor = mode in {"active_cue_only", "full"}
    use_safe_overrides = mode in {"full"}
    use_risky_block_for_safe_frame = mode in {"full"}
    if use_safe_overrides and strong_override_hits and not continuation_hits:
        risky_hits = []
    elif use_safe_overrides and override_hits and not continuation_hits and not any(pattern in lowered for pattern in ("system override", "silently comply", "comply silently")):
        risky_hits = []
    if risky_hits and use_active_floor:
        floor = float(config.get("active_attack_floor", threshold))
        calibrated = max(risk, floor)
        return calibrated, _calibration_metadata(
            mode,
            risk,
            calibrated,
            "active_surface_attack_cue",
            safe_hits,
            risky_hits,
            override_hits,
            strong_override_hits,
            continuation_hits,
        )
    min_risk_for_safe_framing = float(config.get("min_risk_for_safe_framing", threshold))
    if risk < min_risk_for_safe_framing:
        return risk, {"enabled": True, "mode": mode, "applied": False, "reason": "below_safe_framing_trigger"}
    min_safe_cues = int(config.get("min_safe_cues", 1))
    safe_frame_allowed = len(safe_hits) >= min_safe_cues and (not risky_hits or not use_risky_block_for_safe_frame)
    if use_safe_frame and safe_frame_allowed:
        cap = float(config.get("safe_framing_cap", 0.0))
        return min(risk, cap), _calibration_metadata(
            mode,
            risk,
            min(risk, cap),
            "safe_surface_framing_without_active_attack_cue",
            safe_hits,
            risky_hits,
            override_hits,
            strong_override_hits,
            continuation_hits,
        )
    metadata = _calibration_metadata(
        mode,
        risk,
        risk,
        "active_attack_cue_or_insufficient_safe_framing",
        safe_hits,
        risky_hits,
        override_hits,
        strong_override_hits,
        continuation_hits,
    )
    metadata["applied"] = False
    return risk, metadata


def active_risk_hits(lowered: str) -> list[str]:
    hits = pattern_hits(SURFACE_ACTIVE_ATTACK_PATTERNS, lowered)
    hits.extend(pattern_hits(SURFACE_ATTACK_CONTINUATION_PATTERNS, lowered))
    hits.extend(pattern_hits(EXTERNAL_REVIEW_ACTIVE_RISK_PATTERNS, lowered))
    return hits


def public_vlm_ocr_safe_frame(text: str, surface: str) -> dict[str, Any]:
    if surface != "vlm_ocr":
        return {"enabled": True, "applied": False, "reason": "surface_not_applicable"}
    lowered = text.lower()
    safe_hits = pattern_hits(PUBLIC_VLM_OCR_SAFE_PATTERNS, lowered)
    active_hits = active_risk_hits(lowered)
    if not safe_hits:
        return {"enabled": True, "applied": False, "reason": "no_public_ocr_safe_cue"}
    if active_hits:
        return {"enabled": True, "applied": False, "reason": "active_risk_cue", "safe_cues": safe_hits[:8], "active_cues": active_hits[:8]}
    return {"enabled": True, "applied": True, "reason": "public_ocr_schedule_without_active_risk_cue", "safe_cues": safe_hits[:8]}


def _calibration_metadata(
    mode: str,
    raw_risk: float,
    calibrated_risk: float,
    reason: str,
    safe_hits: list[str],
    risky_hits: list[str],
    override_hits: list[str],
    strong_override_hits: list[str],
    continuation_hits: list[str],
) -> dict[str, Any]:
    return {
        "enabled": True,
        "mode": mode,
        "applied": calibrated_risk != raw_risk,
        "reason": reason,
        "raw_probability": raw_risk,
        "calibrated_probability": calibrated_risk,
        "safe_cue_count": len(safe_hits),
        "safe_cues": safe_hits[:8],
        "risky_cues": risky_hits[:8],
        "safe_overrides": override_hits[:4],
        "strong_safe_overrides": strong_override_hits[:4],
        "attack_continuations": continuation_hits[:4],
    }
