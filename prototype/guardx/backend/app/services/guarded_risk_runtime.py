import os
from typing import Any

from app.config import SETTINGS
from app.guards import (
    chat_vlm_route_adapter,
    embedding_guard_online,
    external_calibration_adapter,
    rag_vlm_safe_frame_adapter,
    review_fallback,
    safe_frame_adapter,
    segment_role_adapter,
    segment_role_features,
    zh_rag_safe_frame_adapter,
)
from app.models import AnalysisResult
from app.services.guarded_risk_patterns import (
    SURFACE_ACTIVE_ATTACK_PATTERNS,
    SURFACE_ATTACK_CONTINUATION_PATTERNS,
    EXTERNAL_REVIEW_SAFE_FRAME_PATTERNS,
    EXTERNAL_REVIEW_STRONG_SAFE_FRAME_PATTERNS,
    EXTERNAL_REVIEW_ACTIVE_RISK_PATTERNS,
)
from app.services.guarded_risk_recovery import (
    merge_risk_with_embedding_route,
    recover_benign_vlm_visual_training,
)
from app.services.guarded_risk_surface_calibration import (
    active_risk_hits as _active_risk_hits,
    pattern_hits as _pattern_hits,
    public_vlm_ocr_safe_frame as _public_vlm_ocr_safe_frame,
    surface_calibration,
    surface_calibration_mode,
)
from app.services.qwen3_online_bridge import analyze_external_qwen3_online, external_qwen3_enabled

def _external_safe_review_allow(
    text: str,
    surface: str,
    policy: dict[str, Any],
    route: str,
    online_risk: float,
    adapter_score: float,
    online_high: bool,
    adapter_high: bool,
) -> dict[str, Any]:
    config = dict(policy.get("external_calibration", {})).get("safe_review_allow", {})
    if not isinstance(config, dict) or not config.get("enabled", False):
        return {"enabled": False, "applied": False, "reason": "disabled"}
    allowed_surfaces = {str(item) for item in config.get("surfaces", ["default", "chat"])}
    if surface not in allowed_surfaces:
        return {"enabled": True, "applied": False, "reason": "surface_not_applicable"}
    if route != "review":
        return {"enabled": True, "applied": False, "reason": "not_review_route"}
    chat_like_surfaces = {str(item) for item in config.get("chat_like_surfaces", ["default", "chat"])}
    surface_review_surfaces = {str(item) for item in config.get("surface_review_surfaces", ["rag", "vlm_ocr"])}
    allow_adapter_only_chat = surface in chat_like_surfaces and (not online_high) and adapter_high
    max_surface_adapter_score = float(config.get("max_surface_adapter_score", 0.35))
    allow_low_adapter_chat = surface in chat_like_surfaces and online_high and (not adapter_high) and adapter_score <= max_surface_adapter_score
    allow_low_adapter_surface = surface in surface_review_surfaces and online_high and (not adapter_high) and adapter_score <= max_surface_adapter_score
    if not (allow_adapter_only_chat or allow_low_adapter_chat or allow_low_adapter_surface):
        return {
            "enabled": True,
            "applied": False,
            "reason": "conflict_type_not_recoverable",
            "online_high": online_high,
            "adapter_high": adapter_high,
            "adapter_score": round(adapter_score, 6),
        }
    learned_config = dict(dict(policy.get("external_calibration", {})).get("learned_safe_frame_adapter", {}))
    learned = safe_frame_adapter.score_text(text, surface)
    if learned.get("enabled") and learned_config.get("prefer_for_review_allow", True):
        max_learned_online_risk = float(learned_config.get("max_review_allow_online_risk", 0.55))
        if allow_adapter_only_chat and online_risk > max_learned_online_risk:
            return {
                "enabled": True,
                "applied": False,
                "reason": "learned_online_risk_too_high",
                "online_risk": round(online_risk, 6),
                "learned_safe_frame_adapter": learned,
            }
        if learned.get("is_risky"):
            return {
                "enabled": True,
                "applied": False,
                "reason": "learned_adapter_risky",
                "online_risk": round(online_risk, 6),
                "adapter_score": round(adapter_score, 6),
                "learned_safe_frame_adapter": learned,
            }
        return {
            "enabled": True,
            "applied": True,
            "reason": "learned_safe_frame_adapter_allow",
            "online_risk": round(online_risk, 6),
            "adapter_score": round(adapter_score, 6),
            "learned_safe_frame_adapter": learned,
        }
    max_online_risk = float(config.get("max_online_risk", 0.05))
    if allow_adapter_only_chat and online_risk > max_online_risk:
        return {"enabled": True, "applied": False, "reason": "online_risk_too_high", "online_risk": round(online_risk, 6)}
    lowered = text.lower()
    safe_hits = _pattern_hits(EXTERNAL_REVIEW_SAFE_FRAME_PATTERNS, lowered)
    strong_safe_hits = _pattern_hits(EXTERNAL_REVIEW_STRONG_SAFE_FRAME_PATTERNS, lowered)
    hard_active_hits = _pattern_hits(SURFACE_ACTIVE_ATTACK_PATTERNS, lowered)
    active_hits = [*hard_active_hits]
    active_hits.extend(_pattern_hits(SURFACE_ATTACK_CONTINUATION_PATTERNS, lowered))
    active_hits.extend(_pattern_hits(EXTERNAL_REVIEW_ACTIVE_RISK_PATTERNS, lowered))
    min_safe_cues = int(config.get("min_safe_cues", 1))
    if len(safe_hits) + len(strong_safe_hits) < min_safe_cues:
        return {
            "enabled": True,
            "applied": False,
            "reason": "insufficient_safe_frame",
            "adapter_score": round(adapter_score, 6),
            "safe_cue_count": len(safe_hits),
            "safe_cues": safe_hits[:8],
            "strong_safe_cues": strong_safe_hits[:8],
            "active_cues": active_hits[:8],
        }
    continuation_hits = _pattern_hits(SURFACE_ATTACK_CONTINUATION_PATTERNS, lowered)
    continuation_hits.extend(_pattern_hits(EXTERNAL_REVIEW_ACTIVE_RISK_PATTERNS[:1], lowered))
    safe_frame_can_cancel_active = (
        allow_low_adapter_surface
        and len(strong_safe_hits) >= int(config.get("min_strong_surface_safe_cues", 1))
        and not continuation_hits
    )
    if active_hits and not safe_frame_can_cancel_active:
        return {
            "enabled": True,
            "applied": False,
            "reason": "active_risk_cue",
            "adapter_score": round(adapter_score, 6),
            "safe_cue_count": len(safe_hits),
            "safe_cues": safe_hits[:8],
            "strong_safe_cues": strong_safe_hits[:8],
            "active_cues": active_hits[:8],
        }
    return {
        "enabled": True,
        "applied": True,
        "reason": "adapter_only_conflict_with_safe_frame",
        "online_risk": round(online_risk, 6),
        "adapter_score": round(adapter_score, 6),
        "safe_cue_count": len(safe_hits),
        "safe_cues": safe_hits[:8],
        "strong_safe_cues": strong_safe_hits[:8],
        "active_cues": active_hits[:8],
        "active_cues_cancelled_by_safe_frame": bool(active_hits),
    }


def _external_active_route_override(
    text: str,
    surface: str,
    policy: dict[str, Any],
    route: str,
    adapter_score: float,
) -> dict[str, Any]:
    config = dict(dict(policy.get("external_calibration", {})).get("active_route_override", {}))
    if not config.get("enabled", False):
        return {"enabled": False, "applied": False, "reason": "disabled"}
    if route != "allow":
        return {"enabled": True, "applied": False, "reason": "not_allow_route"}
    surfaces = {str(item) for item in config.get("surfaces", ["rag", "vlm_ocr"])}
    if surface not in surfaces:
        return {"enabled": True, "applied": False, "reason": "surface_not_applicable"}
    lowered = text.lower()
    hard_active_hits = _pattern_hits(SURFACE_ACTIVE_ATTACK_PATTERNS, lowered)
    active_hits = [*hard_active_hits]
    active_hits.extend(_pattern_hits(SURFACE_ATTACK_CONTINUATION_PATTERNS, lowered))
    active_hits.extend(_pattern_hits(EXTERNAL_REVIEW_ACTIVE_RISK_PATTERNS, lowered))
    learned_config = dict(dict(policy.get("external_calibration", {})).get("learned_safe_frame_adapter", {}))
    learned = safe_frame_adapter.score_text(text, surface)
    if learned.get("enabled") and learned_config.get("risky_override_allow_route", True) and learned.get("is_risky"):
        return {
            "enabled": True,
            "applied": True,
            "reason": "learned_adapter_risky_on_allow_route",
            "adapter_score": round(adapter_score, 6),
            "active_cues": active_hits[:8],
            "learned_safe_frame_adapter": learned,
        }
    if not active_hits:
        return {"enabled": True, "applied": False, "reason": "no_active_cue", "learned_safe_frame_adapter": learned}
    strong_safe_hits = _pattern_hits(EXTERNAL_REVIEW_STRONG_SAFE_FRAME_PATTERNS, lowered)
    max_safe_adapter_score = float(config.get("max_safe_adapter_score", 0.35))
    min_strong_safe_cues = int(config.get("min_strong_safe_cues", 1))
    continuation_hits = _pattern_hits(SURFACE_ATTACK_CONTINUATION_PATTERNS, lowered)
    continuation_hits.extend(_pattern_hits(EXTERNAL_REVIEW_ACTIVE_RISK_PATTERNS[:1], lowered))
    continuation_hits.extend(hard_active_hits)
    if learned.get("enabled") and learned_config.get("safe_cancel_active_route", True) and learned.get("is_safe_frame") and not continuation_hits:
        return {
            "enabled": True,
            "applied": False,
            "reason": "learned_safe_frame_cancelled_active_cue",
            "adapter_score": round(adapter_score, 6),
            "active_cues": active_hits[:8],
            "learned_safe_frame_adapter": learned,
        }
    strong_safe_cancel = adapter_score <= max_safe_adapter_score and len(strong_safe_hits) >= min_strong_safe_cues and not continuation_hits
    if strong_safe_cancel:
        return {
            "enabled": True,
            "applied": False,
            "reason": "strong_safe_frame_cancelled_active_cue",
            "adapter_score": round(adapter_score, 6),
            "active_cues": active_hits[:8],
            "strong_safe_cues": strong_safe_hits[:8],
        }
    return {
        "enabled": True,
        "applied": True,
        "reason": "active_cue_on_allow_route",
        "adapter_score": round(adapter_score, 6),
        "active_cues": active_hits[:8],
        "strong_safe_cues": strong_safe_hits[:8],
        "continuation_cues": continuation_hits[:8],
    }


def maybe_merge_online_embedding(
    base: AnalysisResult,
    text: str,
    surface: str = "default",
    segments: list[tuple[str, str]] | None = None,
) -> AnalysisResult:
    if os.environ.get("GUARDX_QWEN3_ONLINE", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return base
    try:
        online = (
            analyze_external_qwen3_online(text, surface=surface, segments=segments)
            if external_qwen3_enabled()
            else embedding_guard_online.analyze(text, surface=surface, segments=segments)
        )
    except Exception as exc:
        merged_metadata = {**base.metadata, "qwen3_joint_online_error": str(exc)}
        return AnalysisResult(risk_score=base.risk_score, labels=[*base.labels, "qwen3_joint_online_error"], evidence=base.evidence, metadata=merged_metadata)
    policy = embedding_guard_online.load_online_policy()
    surface_thresholds = dict(policy.get("surface_thresholds", {}))
    calibration_mode = surface_calibration_mode(policy)
    surface_threshold = None if calibration_mode == "no_calibration" else surface_thresholds.get(surface)
    threshold = float(surface_threshold if surface_threshold is not None else online.metadata.get("threshold", policy.get("threshold", 0.638943)))
    online_risk = online.risk_score
    online_risk, calibration_metadata = surface_calibration(text, surface, policy, online_risk, threshold)
    segment_dual_head = dict(online.metadata.get("segment_aware_dual_head", {}))
    segment_policy = dict(policy.get("segment_aware_dual_head", {}))
    segment_profile_selector = dict(segment_dual_head.get("profile_selector", {}))
    segment_profile_suppressed = bool(segment_profile_selector.get("suppression_applied"))
    segment_dual_head_risky = bool(segment_dual_head.get("enabled") and segment_dual_head.get("is_risky"))
    segment_dual_head_safe = bool(segment_dual_head.get("enabled") and segment_dual_head.get("is_safe_frame") and not segment_dual_head_risky)
    embedding_mlp = dict(online.metadata.get("safe_frame_embedding_mlp", {}))
    public_vlm_safe_frame = _public_vlm_ocr_safe_frame(text, surface)
    if public_vlm_safe_frame.get("applied") and segment_dual_head_risky and embedding_mlp.get("is_safe_frame"):
        segment_dual_head = {
            **segment_dual_head,
            "is_risky": False,
            "is_safe_frame": True,
            "public_vlm_ocr_safe_frame_override": public_vlm_safe_frame,
        }
        segment_dual_head_risky = False
        segment_dual_head_safe = True
    segment_route_surfaces = {str(item) for item in segment_policy.get("safe_frame_route_surfaces", ["rag", "vlm_ocr", "agent_tool"])}
    segment_suppression_route_surfaces = {
        str(item) for item in segment_policy.get("suppression_route_allow_surfaces", ["agent_tool"])
    }
    segment_surface = "chat" if surface == "default" else surface
    segment_safe_frame_risk_cap = float(segment_policy.get("safe_frame_risk_cap", 0.0))
    online_labels = [label for label in online.labels if label != "embedding_jailbreak_risk"]
    online.metadata = {
        **online.metadata,
        "segment_aware_dual_head": segment_dual_head,
        "public_vlm_ocr_safe_frame": public_vlm_safe_frame,
        "raw_probability": online.metadata.get("probability"),
        "calibrated_probability": online_risk,
        "surface": surface,
        "segment_surface": segment_surface,
        "surface_threshold": threshold if surface_threshold is not None else None,
        "default_threshold": online.metadata.get("threshold"),
        "effective_threshold": threshold,
        "surface_calibration_mode": calibration_mode,
        "surface_calibration": calibration_metadata,
    }
    if segment_dual_head_safe and segment_surface in segment_route_surfaces:
        previous_risk = online_risk
        online_risk = min(online_risk, segment_safe_frame_risk_cap)
        online_labels.append("embedding_segment_safe_frame_allow")
        calibration_metadata = {
            **calibration_metadata,
            "segment_aware_dual_head_cap": {
                "enabled": True,
                "applied": True,
                "previous_risk": round(previous_risk, 6),
                "risk_cap": round(segment_safe_frame_risk_cap, 6),
                "safe_frame_score": segment_dual_head.get("safe_frame_score"),
                "active_intent_score": segment_dual_head.get("active_intent_score"),
            },
        }
        online.metadata["calibrated_probability"] = online_risk
        online.metadata["surface_calibration"] = calibration_metadata
    if online_risk >= threshold:
        online_labels.append("embedding_jailbreak_risk")
    external_calibration = external_calibration_adapter.score_text(text, surface, online.metadata, online_labels)
    lowered_text = text.lower()
    route_strong_safe_hits = _pattern_hits(EXTERNAL_REVIEW_STRONG_SAFE_FRAME_PATTERNS, lowered_text)
    route_has_strong_safe_frame = bool(route_strong_safe_hits)
    route = "legacy"
    routed_risk = online_risk
    if external_calibration.get("enabled"):
        learned_safe_frame = safe_frame_adapter.score_text(text, surface)
        if learned_safe_frame.get("enabled"):
            external_calibration["learned_safe_frame_adapter"] = learned_safe_frame
        if embedding_mlp.get("enabled"):
            external_calibration["embedding_safe_frame_mlp"] = embedding_mlp
        calibration_config = dict(policy.get("external_calibration", {}))
        chat_vlm_route = chat_vlm_route_adapter.score_text(text, surface, online.metadata, online_labels)
        if chat_vlm_route.get("enabled"):
            external_calibration["chat_vlm_route_adapter"] = chat_vlm_route
        rag_vlm_safe_frame = rag_vlm_safe_frame_adapter.score_text(text, surface, online.metadata, online_labels)
        if rag_vlm_safe_frame.get("enabled"):
            external_calibration["rag_vlm_safe_frame_adapter"] = rag_vlm_safe_frame
        zh_rag_safe_frame = zh_rag_safe_frame_adapter.score_text(text, surface, online.metadata, online_labels)
        if zh_rag_safe_frame.get("enabled"):
            external_calibration["zh_rag_safe_frame_adapter"] = zh_rag_safe_frame
        learned_segment_role = segment_role_adapter.score_text(text, surface, online.metadata, online_labels, segments)
        if learned_segment_role.get("enabled"):
            external_calibration["segment_role_adapter"] = learned_segment_role
        chat_vlm_config = dict(calibration_config.get("chat_vlm_route_adapter", {}))
        chat_vlm_active_surfaces = {str(item) for item in chat_vlm_config.get("active_surfaces", ["chat", "vlm_ocr"])}
        chat_vlm_safe_surfaces = {str(item) for item in chat_vlm_config.get("safe_surfaces", ["vlm_ocr"])}
        chat_vlm_active_signal = bool(chat_vlm_route.get("enabled") and chat_vlm_route.get("is_risky") and surface in chat_vlm_active_surfaces)
        chat_vlm_safe_signal = bool(chat_vlm_route.get("enabled") and chat_vlm_route.get("is_safe_frame") and surface in chat_vlm_safe_surfaces)
        segment_role_config = dict(calibration_config.get("segment_role_adapter", {}))
        segment_role_adapter_surfaces = {
            str(item) for item in segment_role_config.get("active_surfaces", ["chat", "agent_tool", "rag", "vlm_ocr"])
        }
        segment_role_learned_bypass_signal = bool(
            learned_segment_role.get("enabled")
            and learned_segment_role.get("is_bypass")
            and "bypass" in set(learned_segment_role.get("active_heads", ["bypass"]))
            and surface in segment_role_adapter_surfaces
        )
        agent_dispatch_override_config = dict(calibration_config.get("agent_active_dispatch_route_override", {}))
        agent_active_dispatch_signal = False
        agent_active_dispatch_metadata: dict[str, Any] = {}
        if (
            surface == "agent_tool"
            and bool(agent_dispatch_override_config.get("enabled", False))
            and not segment_profile_suppressed
        ):
            role_features = segment_role_features.extract_role_feature_dict(text, surface, segments)
            has_active_dispatch = bool(
                role_features.get("agent_has_replay_true", 0.0)
                or role_features.get("agent_has_release_queue", 0.0)
                or role_features.get("agent_has_tool_execution", 0.0)
            )
            has_hold_suppression_frame = bool(
                role_features.get("agent_has_hold_queue", 0.0)
                or role_features.get("agent_has_missing_confirmation", 0.0)
                or role_features.get("agent_has_dispatch_false", 0.0)
                or role_features.get("agent_has_tool_call_none", 0.0)
            )
            agent_active_dispatch_signal = bool(has_active_dispatch and not has_hold_suppression_frame)
            agent_active_dispatch_metadata = {
                "enabled": True,
                "applied": agent_active_dispatch_signal,
                "role_features": {
                    key: role_features.get(key)
                    for key in [
                        "agent_has_replay_true",
                        "agent_has_release_queue",
                        "agent_has_tool_execution",
                        "agent_has_hold_queue",
                        "agent_has_missing_confirmation",
                        "agent_has_dispatch_false",
                        "agent_has_tool_call_none",
                    ]
                },
            }
        role_feature_override_config = dict(calibration_config.get("role_feature_active_route_override", {}))
        role_feature_active_signal = False
        role_feature_active_metadata: dict[str, Any] = {}
        if bool(role_feature_override_config.get("enabled", False)):
            role_features = segment_role_features.extract_role_feature_dict(text, surface, segments)
            role_active_reasons: list[str] = []
            rag_denied_bypass = any(
                cue in lowered_text
                for cue in [
                    "ignore execute=false",
                    "despite execute=false",
                    "ignore classify_only",
                    "despite classify_only",
                    "忽略 execute=false",
                    "无视 execute=false",
                    "即使出现 execute=false",
                    "忽略只分类",
                    "无视只分类",
                    "忽略不执行",
                    "无视不执行",
                    "忽略 allowed_action=classify_only",
                    "无视 allowed_action=classify_only",
                    "即使 allowed_action=classify_only",
                ]
            )
            if (
                surface == "chat"
                and bool(role_feature_override_config.get("chat_active_table", True))
                and role_features.get("table_has_active_cell", 0.0)
                and (
                    role_features.get("has_execute_allowed_word", 0.0)
                    or role_features.get("has_active_operation_word", 0.0)
                )
            ):
                role_active_reasons.append("chat_active_table")
            if (
                surface == "rag"
                and bool(role_feature_override_config.get("rag_source_priority", True))
                and role_features.get("rag_has_source_priority_system", 0.0)
                and (
                    role_features.get("rag_has_execute_now", 0.0)
                    or role_features.get("rag_has_zh_source_priority", 0.0)
                    or role_features.get("rag_has_source_override", 0.0)
                )
                and (
                    not role_features.get("rag_has_execute_false", 0.0)
                    or rag_denied_bypass
                )
            ):
                role_active_reasons.append("rag_source_priority_system")
            if (
                surface == "rag"
                and bool(role_feature_override_config.get("rag_source_override", True))
                and role_features.get("rag_has_source_override", 0.0)
                and (
                    role_features.get("has_active_operation_word", 0.0)
                    or role_features.get("rag_has_execute_now", 0.0)
                )
                and (
                    not role_features.get("rag_has_execute_false", 0.0)
                    or rag_denied_bypass
                )
            ):
                role_active_reasons.append("rag_source_override_active")
            if (
                surface == "vlm_ocr"
                and bool(role_feature_override_config.get("vlm_active_overlay", True))
                and (
                    role_features.get("ocr_has_sticker_command", 0.0)
                    or role_features.get("ocr_has_active_overlay", 0.0)
                )
                and not role_features.get("ocr_has_safe_card", 0.0)
            ):
                role_active_reasons.append("vlm_active_overlay")
            role_feature_active_signal = bool(role_active_reasons)
            role_feature_active_metadata = {
                "enabled": True,
                "applied": role_feature_active_signal,
                "reasons": role_active_reasons,
                "role_features": {
                    key: role_features.get(key)
                    for key in [
                        "table_has_active_cell",
                        "has_execute_allowed_word",
                        "has_active_operation_word",
                        "rag_has_source_priority_system",
                        "rag_has_execute_now",
                        "rag_has_zh_source_priority",
                        "rag_has_source_override",
                        "rag_has_execute_false",
                        "has_active_operation_word",
                        "ocr_has_sticker_command",
                        "ocr_has_active_overlay",
                        "ocr_has_safe_card",
                    ]
                },
            }
            external_calibration["role_feature_active_route_override"] = role_feature_active_metadata
        rag_vlm_safe_config = dict(calibration_config.get("rag_vlm_safe_frame_adapter", {}))
        rag_vlm_safe_surfaces = {str(item) for item in rag_vlm_safe_config.get("safe_surfaces", ["rag"])}
        rag_vlm_safe_recovery_signal = bool(
            rag_vlm_safe_frame.get("enabled")
            and rag_vlm_safe_frame.get("is_safe_frame")
            and surface in rag_vlm_safe_surfaces
        )
        zh_rag_safe_config = dict(calibration_config.get("zh_rag_safe_frame_adapter", {}))
        zh_rag_safe_surfaces = {str(item) for item in zh_rag_safe_config.get("safe_surfaces", ["rag"])}
        zh_rag_safe_recovery_signal = bool(
            zh_rag_safe_frame.get("enabled")
            and zh_rag_safe_frame.get("is_safe_frame")
            and surface in zh_rag_safe_surfaces
        )
        rag_safe_recovery_signal = bool(rag_vlm_safe_recovery_signal or zh_rag_safe_recovery_signal)
        routing_enabled = bool(calibration_config.get("routing_enabled", False))
        adapter_score = float(external_calibration.get("score", 0.0))
        adapter_threshold = float(external_calibration.get("threshold", 0.5))
        online_high = online_risk >= threshold
        adapter_high = adapter_score >= adapter_threshold
        if online_high and adapter_high:
            mlp_block_downgrade = False
            mlp_config = dict(policy.get("safe_frame_embedding_mlp", {}))
            if embedding_mlp.get("enabled"):
                mlp_block_downgrade = (
                    float(embedding_mlp.get("score", 1.0)) <= float(mlp_config.get("block_downgrade_max_score", -1.0))
                    and route_has_strong_safe_frame
                )
            learned_frame_downgrade = (
                learned_safe_frame.get("enabled")
                and learned_safe_frame.get("is_safe_frame")
                and not embedding_mlp.get("is_risky", False)
                and route_has_strong_safe_frame
            )
            learned_block_downgrade = bool(
                (learned_frame_downgrade or mlp_block_downgrade)
                and bool(dict(calibration_config.get("learned_safe_frame_adapter", {})).get("allow_block_to_allow", False))
            )
            if learned_block_downgrade:
                route = "allow"
                routed_risk = min(online_risk, float(calibration_config.get("review_allow_risk", 0.0)))
                online_labels.extend(["embedding_route_allow", "embedding_learned_safe_frame_block_downgrade"])
                external_calibration["learned_block_downgrade"] = {
                    "enabled": True,
                    "applied": True,
                    "reason": "learned_safe_frame_adapter_downgraded_block_route",
                    "online_risk": round(online_risk, 6),
                    "adapter_score": round(adapter_score, 6),
                    "strong_safe_cues": route_strong_safe_hits[:8],
                }
            else:
                route = "block"
                routed_risk = max(online_risk, adapter_score)
                online_labels.append("embedding_route_block")
        elif (not online_high) and (not adapter_high):
            route = "allow"
            routed_risk = min(online_risk, adapter_score)
            online_labels.append("embedding_route_allow")
        else:
            route = "review"
            review_risk = float(calibration_config.get("review_risk", 0.45))
            routed_risk = max(review_risk, min(online_risk, threshold - 1e-6))
            online_labels.append("embedding_route_review")
            safe_review_allow = _external_safe_review_allow(text, surface, policy, route, online_risk, adapter_score, online_high, adapter_high)
            if safe_review_allow.get("applied") and embedding_mlp.get("is_risky"):
                safe_review_allow = {
                    **safe_review_allow,
                    "applied": False,
                    "reason": "embedding_mlp_risky_cancelled_review_allow",
                    "embedding_safe_frame_mlp": embedding_mlp,
                }
            if safe_review_allow.get("applied") and segment_dual_head_risky:
                safe_review_allow = {
                    **safe_review_allow,
                    "applied": False,
                    "reason": "segment_active_intent_cancelled_review_allow",
                    "segment_aware_dual_head": segment_dual_head,
                }
            if not safe_review_allow.get("applied") and embedding_mlp.get("enabled") and not embedding_mlp.get("is_risky", False):
                mlp_config = dict(policy.get("safe_frame_embedding_mlp", {}))
                try:
                    mlp_review_allow = (
                        float(embedding_mlp.get("score", 1.0)) <= float(mlp_config.get("block_downgrade_max_score", -1.0))
                        and route_has_strong_safe_frame
                    )
                except (TypeError, ValueError):
                    mlp_review_allow = False
                if mlp_review_allow:
                    safe_review_allow = {
                        **safe_review_allow,
                        "enabled": True,
                        "applied": True,
                        "reason": "embedding_mlp_strong_safe_frame_review_allow",
                        "embedding_safe_frame_mlp": embedding_mlp,
                        "strong_safe_cues": route_strong_safe_hits[:8],
                    }
            if safe_review_allow.get("applied"):
                route = "allow"
                routed_risk = min(online_risk, float(calibration_config.get("review_allow_risk", 0.0)))
                online_labels = [label for label in online_labels if label != "embedding_route_review"]
                online_labels.extend(["embedding_route_allow", "embedding_review_safe_frame_allow"])
            external_calibration["safe_review_allow"] = safe_review_allow
        active_route_override = _external_active_route_override(text, surface, policy, route, adapter_score)
        if route == "allow" and embedding_mlp.get("is_risky"):
            if segment_dual_head_safe and segment_surface in segment_route_surfaces and not _active_risk_hits(lowered_text):
                active_route_override = {
                    **active_route_override,
                    "enabled": True,
                    "applied": False,
                    "reason": "segment_safe_frame_cancelled_embedding_mlp_risky",
                    "embedding_safe_frame_mlp": embedding_mlp,
                    "segment_aware_dual_head": segment_dual_head,
                }
            else:
                active_route_override = {
                    **active_route_override,
                    "enabled": True,
                    "applied": True,
                    "reason": "embedding_mlp_risky_on_allow_route",
                    "embedding_safe_frame_mlp": embedding_mlp,
                }
        if route == "allow" and segment_dual_head_risky:
            active_route_override = {
                **active_route_override,
                "enabled": True,
                "applied": True,
                "reason": "segment_active_intent_on_allow_route",
                "segment_aware_dual_head": segment_dual_head,
            }
        if (
            route in {"allow", "review"}
            and surface == "agent_tool"
            and agent_active_dispatch_signal
        ):
            active_route_override = {
                **active_route_override,
                "enabled": True,
                "applied": True,
                "reason": "agent_active_dispatch_on_allow_route",
                "risk_floor": threshold,
                **agent_active_dispatch_metadata,
            }
        if route in {"allow", "review"} and chat_vlm_active_signal:
            active_route_override = {
                **active_route_override,
                "enabled": True,
                "applied": True,
                "reason": "chat_vlm_learned_active_route_adapter",
                "risk_floor": threshold,
                "chat_vlm_route_adapter": chat_vlm_route,
            }
        if route in {"allow", "review"} and role_feature_active_signal:
            active_route_override = {
                **active_route_override,
                "enabled": True,
                "applied": True,
                "reason": "role_feature_active_route_override",
                "risk_floor": threshold,
                **role_feature_active_metadata,
            }
        if route in {"allow", "review"} and segment_role_learned_bypass_signal:
            active_route_override = {
                **active_route_override,
                "enabled": True,
                "applied": True,
                "reason": "segment_role_learned_bypass_adapter",
                "risk_floor": threshold,
                "segment_role_adapter": learned_segment_role,
            }
        if (
            active_route_override.get("applied")
            and surface == "rag"
            and bool(rag_vlm_safe_config.get("cancel_role_feature_override", True))
            and active_route_override.get("reason") == "role_feature_active_route_override"
            and rag_safe_recovery_signal
            and bool(role_feature_active_metadata.get("reasons"))
        ):
            active_route_override = {
                **active_route_override,
                "applied": False,
                "reason": "rag_safe_frame_adapter_cancelled_role_feature_override",
                "previous_reason": "role_feature_active_route_override",
                "rag_vlm_safe_frame_adapter": rag_vlm_safe_frame,
                "zh_rag_safe_frame_adapter": zh_rag_safe_frame,
                "role_feature_active_route_override": role_feature_active_metadata,
            }
        mlp_strong_safe = False
        if route == "allow" and embedding_mlp.get("enabled") and not embedding_mlp.get("is_risky", False):
            mlp_config = dict(policy.get("safe_frame_embedding_mlp", {}))
            try:
                mlp_strong_safe = (
                    float(embedding_mlp.get("score", 1.0)) <= float(mlp_config.get("block_downgrade_max_score", -1.0))
                    and route_has_strong_safe_frame
                )
            except (TypeError, ValueError):
                mlp_strong_safe = False
        if (
            active_route_override.get("applied")
            and mlp_strong_safe
            and active_route_override.get("reason") not in {"agent_active_dispatch_on_allow_route", "role_feature_active_route_override"}
        ):
            active_route_override = {
                **active_route_override,
                "applied": False,
                "reason": "embedding_mlp_strong_safe_cancelled_active_override",
                "previous_reason": active_route_override.get("reason"),
                "embedding_safe_frame_mlp": embedding_mlp,
                "strong_safe_cues": route_strong_safe_hits[:8],
            }
        if active_route_override.get("applied"):
            route = "review"
            review_risk = max(float(calibration_config.get("review_risk", 0.45)), float(active_route_override.get("risk_floor", 0.0)))
            routed_risk = max(routed_risk, review_risk)
            online_labels = [label for label in online_labels if label != "embedding_route_allow"]
            online_labels.extend(["embedding_route_review", "embedding_active_route_override"])
        external_calibration["active_route_override"] = active_route_override
        external_calibration = {
            **external_calibration,
            "routing_enabled": routing_enabled,
            "route": route,
            "online_high": online_high,
            "adapter_high": adapter_high,
            "routed_probability": round(routed_risk, 6),
        }
        if route == "review" and dict(policy.get("review_fallback", {})).get("enabled", False):
            fallback = review_fallback.review(text, external_calibration)
            external_calibration["review_fallback"] = fallback
            if fallback.get("decision") == "block":
                routed_risk = max(routed_risk, float(fallback.get("risk", threshold)))
                online_labels.append("embedding_review_fallback_block")
            elif fallback.get("decision") == "allow":
                routed_risk = min(routed_risk, float(calibration_config.get("review_allow_risk", 0.0)))
                online_labels.append("embedding_review_fallback_allow")
            else:
                online_labels.append("embedding_review_fallback_review")
            external_calibration["routed_probability"] = round(routed_risk, 6)
        if (
            segment_dual_head_safe
            and surface in segment_route_surfaces
            and bool(segment_policy.get("safe_frame_route_allow", True))
            and not agent_active_dispatch_signal
            and not chat_vlm_active_signal
            and not segment_role_learned_bypass_signal
            and (not role_feature_active_signal or (surface == "rag" and rag_safe_recovery_signal))
        ):
            previous_route = route
            previous_routed_risk = routed_risk
            route = "allow"
            routed_risk = min(routed_risk, segment_safe_frame_risk_cap)
            online_labels = [label for label in online_labels if label not in {"embedding_route_block", "embedding_route_review", "embedding_jailbreak_risk"}]
            online_labels.extend(["embedding_route_allow", "embedding_segment_safe_frame_route_allow"])
            external_calibration["segment_safe_frame_route_allow"] = {
                "enabled": True,
                "applied": True,
                "previous_route": previous_route,
                "previous_routed_risk": round(previous_routed_risk, 6),
                "risk_cap": round(segment_safe_frame_risk_cap, 6),
                "segment_aware_dual_head": segment_dual_head,
                "rag_vlm_safe_frame_adapter": rag_vlm_safe_frame if surface == "rag" and rag_vlm_safe_recovery_signal else None,
                "zh_rag_safe_frame_adapter": zh_rag_safe_frame if surface == "rag" and zh_rag_safe_recovery_signal else None,
            }
            external_calibration["route"] = route
            external_calibration["routed_probability"] = round(routed_risk, 6)
        elif segment_dual_head_safe and agent_active_dispatch_signal:
            external_calibration["segment_safe_frame_route_allow"] = {
                "enabled": True,
                "applied": False,
                "reason": "agent_active_dispatch_cancelled_safe_frame_route_allow",
                **agent_active_dispatch_metadata,
                "segment_aware_dual_head": segment_dual_head,
            }
        elif segment_dual_head_safe and chat_vlm_active_signal:
            external_calibration["segment_safe_frame_route_allow"] = {
                "enabled": True,
                "applied": False,
                "reason": "chat_vlm_active_adapter_cancelled_safe_frame_route_allow",
                "chat_vlm_route_adapter": chat_vlm_route,
                "segment_aware_dual_head": segment_dual_head,
            }
        elif segment_dual_head_safe and role_feature_active_signal:
            external_calibration["segment_safe_frame_route_allow"] = {
                "enabled": True,
                "applied": False,
                "reason": "role_feature_active_cancelled_safe_frame_route_allow",
                **role_feature_active_metadata,
                "segment_aware_dual_head": segment_dual_head,
            }
        elif segment_dual_head_safe and segment_role_learned_bypass_signal:
            external_calibration["segment_safe_frame_route_allow"] = {
                "enabled": True,
                "applied": False,
                "reason": "segment_role_learned_bypass_cancelled_safe_frame_route_allow",
                "segment_role_adapter": learned_segment_role,
                "segment_aware_dual_head": segment_dual_head,
            }
        if (
            route in {"block", "review"}
            and chat_vlm_safe_signal
            and not role_feature_active_signal
            and not segment_role_learned_bypass_signal
            and bool(chat_vlm_config.get("safe_route_allow", True))
            and (not bool(chat_vlm_config.get("require_learned_safe_frame", True)) or learned_safe_frame.get("is_safe_frame"))
            and (not bool(chat_vlm_config.get("require_embedding_safe_frame", True)) or not embedding_mlp.get("is_risky", False))
        ):
            previous_route = route
            previous_routed_risk = routed_risk
            route = "allow"
            routed_risk = min(routed_risk, segment_safe_frame_risk_cap)
            online_labels = [
                label
                for label in online_labels
                if label not in {"embedding_route_block", "embedding_route_review", "embedding_jailbreak_risk"}
            ]
            online_labels.extend(["embedding_route_allow", "embedding_chat_vlm_route_adapter_safe_allow"])
            external_calibration["chat_vlm_route_adapter_safe_allow"] = {
                "enabled": True,
                "applied": True,
                "previous_route": previous_route,
                "previous_routed_risk": round(previous_routed_risk, 6),
                "risk_cap": round(segment_safe_frame_risk_cap, 6),
                "chat_vlm_route_adapter": chat_vlm_route,
                "learned_safe_frame_adapter": learned_safe_frame,
                "embedding_safe_frame_mlp": embedding_mlp,
            }
            external_calibration["route"] = route
            external_calibration["routed_probability"] = round(routed_risk, 6)
        if (
            segment_profile_suppressed
            and surface in segment_suppression_route_surfaces
            and bool(segment_policy.get("suppression_route_allow", True))
        ):
            previous_route = route
            previous_routed_risk = routed_risk
            route = "allow"
            routed_risk = min(routed_risk, segment_safe_frame_risk_cap)
            online_labels = [
                label
                for label in online_labels
                if label not in {"embedding_route_block", "embedding_route_review", "embedding_jailbreak_risk"}
            ]
            online_labels.extend(["embedding_route_allow", "embedding_segment_role_profile_selector_suppression_allow"])
            external_calibration["segment_role_profile_selector_suppression_allow"] = {
                "enabled": True,
                "applied": True,
                "previous_route": previous_route,
                "previous_routed_risk": round(previous_routed_risk, 6),
                "risk_cap": round(segment_safe_frame_risk_cap, 6),
                "profile_selector": segment_profile_selector,
            }
            external_calibration["route"] = route
            external_calibration["routed_probability"] = round(routed_risk, 6)
        if routing_enabled:
            online_risk = routed_risk
    if segment_dual_head_risky and bool(segment_policy.get("force_active_intent_floor", True)):
        segment_floor = float(segment_policy.get("risk_floor", 1.0))
        if online_risk < segment_floor:
            online_risk = segment_floor
            online_labels.append("embedding_segment_active_intent_risk")
            calibration_metadata = {
                **calibration_metadata,
                "segment_aware_dual_head_floor": {
                    "enabled": True,
                    "applied": True,
                    "risk_floor": round(segment_floor, 6),
                    "active_intent_score": segment_dual_head.get("active_intent_score"),
                    "safe_frame_score": segment_dual_head.get("safe_frame_score"),
                },
            }
            if external_calibration.get("enabled"):
                external_calibration["segment_aware_dual_head_override"] = {
                    "enabled": True,
                    "applied": True,
                    "reason": "active_intent_head_forced_risk_floor",
                    "risk_floor": round(segment_floor, 6),
                    "previous_route": external_calibration.get("route"),
                    "segment_aware_dual_head": segment_dual_head,
                }
    online.metadata["calibrated_probability"] = online_risk
    online.metadata["surface_calibration"] = calibration_metadata
    merged_metadata = {**base.metadata, "qwen3_joint_online": online.metadata}
    if external_calibration.get("enabled"):
        merged_metadata["qwen3_external_calibration"] = external_calibration
    return AnalysisResult(
        risk_score=max(base.risk_score, online_risk),
        labels=list(dict.fromkeys([*base.labels, *online_labels])),
        evidence=[*base.evidence, *online.evidence],
        metadata=merged_metadata,
    )

__all__ = [
    "maybe_merge_online_embedding",
    "merge_risk_with_embedding_route",
    "recover_benign_vlm_visual_training",
]
