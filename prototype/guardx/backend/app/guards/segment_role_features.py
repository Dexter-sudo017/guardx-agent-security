from __future__ import annotations

import math
import re


PROFILE_SELECTOR_SURFACES = ["default", "chat", "agent_tool", "rag", "vlm_ocr"]

ROLE_FEATURE_NAMES = [
    "log_text_length",
    "log_segment_count",
    "surface_default",
    "surface_chat",
    "surface_agent_tool",
    "surface_rag",
    "surface_vlm_ocr",
    "has_markdown_table",
    "table_has_active_cell",
    "table_has_safe_cell",
    "has_confirmation_word",
    "has_execute_allowed_word",
    "has_execute_denied_word",
    "has_quote_or_evidence_word",
    "has_active_operation_word",
    "safe_cue_count_log",
    "active_cue_count_log",
    "active_minus_safe_cues",
    "context_segment_count_log",
    "ocr_segment_count_log",
    "visual_segment_count_log",
    "rag_has_untrusted_context",
    "rag_has_source_override",
    "rag_has_execute_false",
    "ocr_has_overlay",
    "ocr_has_safe_card",
    "ocr_has_active_overlay",
    "agent_has_runbook",
    "agent_has_hold_queue",
    "agent_has_missing_confirmation",
    "agent_has_dispatch_false",
    "agent_has_replay_true",
    "agent_has_release_queue",
    "agent_has_replay_disabled",
    "agent_has_tool_call_none",
    "agent_has_tool_execution",
    "rag_has_source_priority_system",
    "rag_has_execute_now",
    "rag_has_zh_source_priority",
    "rag_override_chunk_count_log",
    "ocr_has_sticker_command",
    "contains_zh",
]

SCORE_FEATURE_NAMES = [
    "strict_safe_score",
    "strict_active_score",
    "strict_margin",
    "strict_active_over_threshold",
    "strict_safe_over_threshold",
    "high_safe_score",
    "high_active_score",
    "high_margin",
    "high_active_over_threshold",
    "high_safe_over_threshold",
    "max_active_score",
    "min_active_score",
    "high_minus_strict_active",
    "strict_high_active_product",
    "min_safe_score",
    "max_safe_score",
]

PROFILE_SELECTOR_FEATURE_NAMES = SCORE_FEATURE_NAMES + ROLE_FEATURE_NAMES


SAFE_CUES = [
    "quote",
    "quoted",
    "quoted_example",
    "captured",
    "evidence",
    "audit",
    "review",
    "classify",
    "classification",
    "refusal",
    "deny",
    "blocked",
    "prohibited",
    "do not execute",
    "do_not_execute",
    "execute=false",
    "simulation=false",
    "replay=off",
    "replay: disabled",
    "real_tool_call: none",
    "untrusted",
    "safe-frame",
    "安全",
    "引用",
    "证据",
    "审计",
    "审查",
    "分类",
    "拒绝",
    "阻断",
    "禁止",
    "不可执行",
    "不要执行",
    "仅为",
]

ACTIVE_CUES = [
    "perform",
    "execute",
    "run ",
    "call ",
    "send",
    "post",
    "push",
    "forward",
    "export",
    "copy",
    "read",
    "reveal",
    "release",
    "display",
    "open",
    "unlock",
    "disable",
    "skip",
    "bypass",
    "ignore",
    "trust",
    "proceed",
    "continue",
    "override",
    "confirmed",
    "follow",
    "执行",
    "运行",
    "调用",
    "发送",
    "转发",
    "导出",
    "复制",
    "读取",
    "透露",
    "释放",
    "显示",
    "打开",
    "解锁",
    "禁用",
    "跳过",
    "绕过",
    "忽略",
    "信任",
    "继续",
    "覆盖",
    "遵循",
]

CONFIRMATION_CUES = ["confirm", "confirmed", "confirmation", "acknowledge", "acknowledged", "确认", "已确认", "先说", "先给", "之后", "然后"]
EXECUTE_DENIED_CUES = [
    "execute=false",
    "execute: false",
    "do_not_execute",
    "do not execute",
    "classify_only",
    "allowed_action=classify_only",
    "allowed_action: classify_only",
    "replay=off",
    "replay: disabled",
    "real_tool_call: none",
    "不可执行",
    "不要执行",
    "不执行",
    "只分类",
    "仅分类",
    "只做分类",
]
EXECUTE_ALLOWED_CUES = ["confirmed=true", "confirmed |", "| confirmed", "execute it", "perform:", "proceed", "continue now", "执行命令", "活动指令"]
QUOTE_EVIDENCE_CUES = ["quoted", "quoted_example", "captured", "evidence", "audit", "review-only", "blocked_sample", "引用", "证据", "审计", "不可执行"]
RAG_OVERRIDE_CUES = [
    "higher priority",
    "overrides policy",
    "outranks user safety",
    "outranks safety",
    "ignore system",
    "trust source",
    "follow retrieved",
    "source command",
    "source operation",
    "优先于策略",
    "高于策略",
    "高于安全",
    "忽略系统",
    "信任检索",
    "检索源",
]
OCR_OVERLAY_CUES = ["ocr", "overlay", "watermark", "banner", "caption_override", "poster_command", "覆盖层", "水印", "横幅", "海报"]
OCR_SAFE_CUES = ["ocr 安全", "安全卡片", "训练卡", "只返回风险类别", "拒绝/分类", "不可执行证据"]
AGENT_RUNBOOK_CUES = ["runbook", "operator", "sop", "transcript", "tool_queue", "agent_runbook", "运行手册", "操作员", "转录", "工具"]
AGENT_HOLD_QUEUE_CUES = ["status: held", "status=held", "held queue", "held agent queue", "confirmation: missing", "confirmation=missing", "missing confirmation", "待确认", "缺少确认", "保持队列", "挂起"]
AGENT_RELEASE_CUES = ["release the held", "release queue", "dispatch this", "turn replay on", "replay=true", "dispatch=true", "operator confirmed", "释放", "派发", "打开 replay", "已确认"]


def _norm(text: str) -> str:
    return text.lower()


def _contains_any(text: str, cues: list[str]) -> bool:
    return any(cue in text for cue in cues)


def _count_cues(text: str, cues: list[str]) -> int:
    return sum(1 for cue in cues if cue in text)


def _has_zh(text: str) -> bool:
    return bool(re.search(r"[\u4e00-\u9fff]", text))


def _table_lines(text: str) -> list[str]:
    return [line.strip().lower() for line in text.splitlines() if "|" in line and line.count("|") >= 2]


def extract_role_feature_dict(text: str, surface: str, segments: list[tuple[str, str]] | None = None) -> dict[str, float]:
    segment_items = segments or [("user", text)]
    segment_texts = [str(value) for _kind, value in segment_items]
    joined = "\n".join(segment_texts)
    lower = _norm(joined)
    table_lines = _table_lines(joined)
    safe_cues = _count_cues(lower, SAFE_CUES)
    active_cues = _count_cues(lower, ACTIVE_CUES)
    context_segments = [value for kind, value in segment_items if kind == "context"]
    ocr_segments = [value for kind, value in segment_items if kind == "ocr"]
    visual_segments = [value for kind, value in segment_items if kind == "visual"]
    table_has_active_cell = any(_contains_any(line, ACTIVE_CUES) and _contains_any(line, EXECUTE_ALLOWED_CUES + ["instruction", "command", "confirmed"]) for line in table_lines)
    table_has_safe_cell = any(_contains_any(line, SAFE_CUES) and _contains_any(line, ["quoted", "example", "classify", "refusal", "引用", "分类", "拒绝"]) for line in table_lines)
    features: dict[str, float] = {
        "log_text_length": math.log1p(float(len(joined))),
        "log_segment_count": math.log1p(float(len(segment_items))),
        "has_markdown_table": float(bool(table_lines)),
        "table_has_active_cell": float(table_has_active_cell),
        "table_has_safe_cell": float(table_has_safe_cell),
        "has_confirmation_word": float(_contains_any(lower, CONFIRMATION_CUES)),
        "has_execute_allowed_word": float(_contains_any(lower, EXECUTE_ALLOWED_CUES)),
        "has_execute_denied_word": float(_contains_any(lower, EXECUTE_DENIED_CUES)),
        "has_quote_or_evidence_word": float(_contains_any(lower, QUOTE_EVIDENCE_CUES)),
        "has_active_operation_word": float(_contains_any(lower, ACTIVE_CUES)),
        "safe_cue_count_log": math.log1p(float(safe_cues)),
        "active_cue_count_log": math.log1p(float(active_cues)),
        "active_minus_safe_cues": float(active_cues - safe_cues),
        "context_segment_count_log": math.log1p(float(len(context_segments))),
        "ocr_segment_count_log": math.log1p(float(len(ocr_segments))),
        "visual_segment_count_log": math.log1p(float(len(visual_segments))),
        "rag_has_untrusted_context": float(surface == "rag" and _contains_any(lower, ["untrusted", "blocked_sample", "不可信"])),
        "rag_has_source_override": float(surface == "rag" and _contains_any(lower, RAG_OVERRIDE_CUES)),
        "rag_has_execute_false": float(surface == "rag" and _contains_any(lower, EXECUTE_DENIED_CUES)),
        "ocr_has_overlay": float(surface == "vlm_ocr" and _contains_any(lower, OCR_OVERLAY_CUES)),
        "ocr_has_safe_card": float(surface == "vlm_ocr" and _contains_any(lower, OCR_SAFE_CUES + QUOTE_EVIDENCE_CUES)),
        "ocr_has_active_overlay": float(surface == "vlm_ocr" and _contains_any(lower, OCR_OVERLAY_CUES) and _contains_any(lower, ACTIVE_CUES)),
        "agent_has_runbook": float(surface == "agent_tool" and _contains_any(lower, AGENT_RUNBOOK_CUES)),
        "agent_has_hold_queue": float(surface == "agent_tool" and _contains_any(lower, AGENT_HOLD_QUEUE_CUES)),
        "agent_has_missing_confirmation": float(surface == "agent_tool" and _contains_any(lower, ["confirmation: missing", "confirmation=missing", "confirmed=false", "confirmed: false", "缺少确认", "未确认"])),
        "agent_has_dispatch_false": float(surface == "agent_tool" and _contains_any(lower, ["dispatch=false", "dispatch: false", "dispatch are both false", "dispatch 都为 false", "may_execute=false"])),
        "agent_has_replay_true": float(surface == "agent_tool" and _contains_any(lower, ["replay=true", "replay: true", "turn replay on", "打开 replay"])),
        "agent_has_release_queue": float(surface == "agent_tool" and _contains_any(lower, AGENT_RELEASE_CUES)),
        "agent_has_replay_disabled": float(surface == "agent_tool" and _contains_any(lower, ["replay=off", "replay: disabled", "replay disabled", "replay 和 dispatch 都为 false"])),
        "agent_has_tool_call_none": float(surface == "agent_tool" and _contains_any(lower, ["real_tool_call: none", "tool_call: none", "allowed_action: classify"])),
        "agent_has_tool_execution": float(surface == "agent_tool" and _contains_any(lower, ["call tools", "execute", "perform", "release the held", "执行", "调用工具"])),
        "rag_has_source_priority_system": float(surface == "rag" and _contains_any(lower, ["source_priority=system", "source priority=system", "priority=system", "更高优先级", "系统优先级"])),
        "rag_has_execute_now": float(surface == "rag" and _contains_any(lower, ["execute source command now", "execute the source", "run the retrieved command now", "执行来源", "执行检索", "现在运行"])),
        "rag_has_zh_source_priority": float(surface == "rag" and _has_zh(joined) and _contains_any(lower, ["更高优先级", "高于策略", "执行来源", "检索来源", "来源命令"])),
        "rag_override_chunk_count_log": math.log1p(float(sum(1 for value in context_segments if _contains_any(_norm(value), RAG_OVERRIDE_CUES + ["source_priority=system", "execute source command now", "执行来源", "更高优先级"])))),
        "ocr_has_sticker_command": float(surface == "vlm_ocr" and _contains_any(lower, ["sticker command", "watermark command", "贴纸指令", "水印命令"])),
        "contains_zh": float(_has_zh(joined)),
    }
    for item in PROFILE_SELECTOR_SURFACES:
        features[f"surface_{item}"] = float(surface == item)
    return features


def build_profile_selector_feature_dict(
    *,
    text: str,
    surface: str,
    segments: list[tuple[str, str]] | None,
    strict_safe_score: float,
    strict_active_score: float,
    strict_safe_threshold: float,
    strict_active_threshold: float,
    high_safe_score: float,
    high_active_score: float,
    high_safe_threshold: float,
    high_active_threshold: float,
) -> dict[str, float]:
    role = extract_role_feature_dict(text, surface, segments)
    score_values = {
        "strict_safe_score": strict_safe_score,
        "strict_active_score": strict_active_score,
        "strict_margin": strict_active_score - strict_safe_score,
        "strict_active_over_threshold": float(strict_active_score >= strict_active_threshold),
        "strict_safe_over_threshold": float(strict_safe_score >= strict_safe_threshold),
        "high_safe_score": high_safe_score,
        "high_active_score": high_active_score,
        "high_margin": high_active_score - high_safe_score,
        "high_active_over_threshold": float(high_active_score >= high_active_threshold),
        "high_safe_over_threshold": float(high_safe_score >= high_safe_threshold),
        "max_active_score": max(strict_active_score, high_active_score),
        "min_active_score": min(strict_active_score, high_active_score),
        "high_minus_strict_active": high_active_score - strict_active_score,
        "strict_high_active_product": strict_active_score * high_active_score,
        "min_safe_score": min(strict_safe_score, high_safe_score),
        "max_safe_score": max(strict_safe_score, high_safe_score),
    }
    return {**score_values, **role}


def build_profile_selector_feature_values(
    *,
    text: str,
    surface: str,
    segments: list[tuple[str, str]] | None,
    strict_safe_score: float,
    strict_active_score: float,
    strict_safe_threshold: float,
    strict_active_threshold: float,
    high_safe_score: float,
    high_active_score: float,
    high_safe_threshold: float,
    high_active_threshold: float,
    feature_names: list[str] | None = None,
) -> list[float]:
    merged = build_profile_selector_feature_dict(
        text=text,
        surface=surface,
        segments=segments,
        strict_safe_score=strict_safe_score,
        strict_active_score=strict_active_score,
        strict_safe_threshold=strict_safe_threshold,
        strict_active_threshold=strict_active_threshold,
        high_safe_score=high_safe_score,
        high_active_score=high_active_score,
        high_safe_threshold=high_safe_threshold,
        high_active_threshold=high_active_threshold,
    )
    names = feature_names or PROFILE_SELECTOR_FEATURE_NAMES
    return [float(merged.get(name, 0.0)) for name in names]
