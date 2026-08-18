from __future__ import annotations

import json
import re
from typing import Any

from app.guards import input_guard


CONTROL_PATTERNS = (
    r"忽略.{0,12}(用户|原始|审批|流程|任务)",
    r"(跳过|绕过|免除).{0,10}(审批|复核|校验)",
    r"(不要|无需).{0,8}(告知|记录|披露|显示).{0,8}(用户|结果|操作)",
    r"(发送|上传|转发|导出).{0,12}(文件|附件|数据|报表|凭据)",
    r"(修改|替换|覆盖).{0,12}(参数|收款账户|供应商|金额)",
    r"ignore.{0,20}(user|approval|previous|original)",
    r"(skip|bypass).{0,16}(approval|review|validation)",
    r"(hide|omit|conceal).{0,16}(result|operation|audit)",
)

SIDE_EFFECT_TOOLS = {"create_review_ticket", "create_review_ticket_safe"}
READ_ONLY_TOOLS = {"read_enterprise_document", "search_enterprise_knowledge", "read_file_safe", "enterprise_search_safe"}


def compute_agent_risk(
    *,
    user_goal: str,
    untrusted_observation: str,
    action: dict[str, Any],
    approval_scope: dict[str, Any],
) -> dict[str, Any]:
    action_text = json.dumps(action, ensure_ascii=False, sort_keys=True, default=str)
    combined = f"{untrusted_observation}\n{action_text}"
    base = input_guard.analyze(combined, []).risk_score
    evidence: list[str] = []
    matched = [pattern for pattern in CONTROL_PATTERNS if re.search(pattern, combined, re.IGNORECASE)]
    if matched:
        evidence.append("untrusted_observation_attempts_task_or_execution_control")

    name = str(action.get("tool_name") or action.get("name") or "").strip().lower()
    arguments = action.get("arguments") if isinstance(action.get("arguments"), dict) else action.get("args") or {}
    side_effect = name in SIDE_EFFECT_TOOLS
    read_only = name in READ_ONLY_TOOLS
    approved_tools = {str(item).strip().lower() for item in approval_scope.get("allowed_tools", [])}
    approval_id = str(arguments.get("approval_id") or approval_scope.get("approval_id") or "")
    approval_match = name in approved_tools and approval_id.startswith("APPROVED-")

    score = float(base)
    if matched:
        score = max(score, 0.78)
    if side_effect:
        score = max(score, 0.38)
        evidence.append("candidate_has_controlled_side_effect")
        if not approval_match:
            score = max(score, 0.84)
            evidence.append("side_effect_outside_explicit_approval_scope")
    if matched and side_effect:
        score = max(score, 0.94)
    if read_only and not matched:
        score = min(score, 0.18)
        evidence.append("read_only_tool_with_goal_aligned_request")
    if name not in SIDE_EFFECT_TOOLS | READ_ONLY_TOOLS:
        score = max(score, 0.92)
        evidence.append("tool_not_exposed_by_qwen_agent_contract")

    return {
        "score": round(min(1.0, max(0.0, score)), 6),
        "source": "guardx_agent_risk_engine_v1",
        "input_guard_score": round(float(base), 6),
        "task_relation_conflict": bool(matched),
        "side_effect": side_effect,
        "approval_match": approval_match,
        "user_goal": user_goal,
        "evidence": evidence,
    }
