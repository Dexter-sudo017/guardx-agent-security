import json
from typing import Any

from app.guards.side_effect_metadata_guard import analyze_case_metadata_signal
from app.models import ToolDecision
from app.sandbox.tool_policy import load_tool_policy
from app.sandbox.tool_review_rules import (
    high_session_risk_decision,
    review_agent_noop,
    review_db_query,
    review_http_get,
    review_read_file,
    review_register_tool,
    review_shell_exec,
    review_write_file,
    unknown_tool_decision,
)


def _side_effect_surface(tool_name: str, args: dict[str, Any]) -> str:
    surface = str(args.get("_guardx_surface") or "").strip().lower()
    normalized = tool_name.strip().lower()
    if surface in {"agent", "tool_observation", "plugin", "rag"}:
        return surface
    if normalized == "register_tool_safe":
        return "plugin"
    if normalized in {"read_file_safe", "write_file_safe", "http_get_safe", "db_query_safe", "shell_exec_sim"}:
        return "agent"
    return "tool_observation"


def _side_effect_context(tool_name: str, args: dict[str, Any]) -> tuple[dict[str, Any], str]:
    normalized = tool_name.strip().lower()
    surface = _side_effect_surface(tool_name, args)
    public_args = {key: value for key, value in args.items() if not str(key).startswith("_guardx_")}
    text = json.dumps(public_args, ensure_ascii=False, sort_keys=True, default=str)
    metadata_text = " ".join(
        str(value).lower()
        for key, value in args.items()
        if str(key).startswith("_guardx_") and value is not None
    )
    if metadata_text:
        text = f"{text}\nmetadata: {metadata_text}"
    lowered = text.lower()
    hints: list[str] = []
    if normalized == "shell_exec_sim":
        hints.extend(["code_execution_capability", "shell_exec"])
        if any(marker in lowered for marker in ("curl", "wget", "http://", "https://")):
            hints.extend(["network_capability", "network export", "unapproved network"])
        if any(marker in lowered for marker in (".env", "credential", "secret", "token", "api_key", "apikey")):
            hints.extend(["runtime secrets", "credential"])
    elif normalized == "http_get_safe":
        domain = str(args.get("domain") or "").lower()
        allowed_domains = {str(item).lower() for item in load_tool_policy().get("allowed_domains", [])}
        hints.extend(["network_capability", "trusted_network"] if domain in allowed_domains else ["network_capability", "network export", "unapproved network"])
    elif normalized == "db_query_safe":
        hints.extend(["database_capability", "database"])
    elif normalized in {"read_file_safe", "write_file_safe"}:
        hints.append("private workspace")
    if hints:
        text = f"{text}\nside_effect_hints: {' '.join(sorted(set(hints)))}"
    trust_boundary = str(args.get("_guardx_trust_boundary") or f"executor_precheck + {surface} + {normalized}_capability")
    return (
        {
            "surface": surface,
            "trust_boundary": trust_boundary,
            "available_tools": [normalized],
        },
        text,
    )


def side_effect_metadata_decision(tool_name: str, args: dict[str, Any]) -> ToolDecision | None:
    metadata_present = any(str(key).startswith("_guardx_") for key in args)
    if not metadata_present and tool_name != "register_tool_safe":
        return None
    case, text = _side_effect_context(tool_name, args)
    analysis = analyze_case_metadata_signal(case, text)
    if analysis.risk_score <= 0 or not analysis.labels:
        return None
    return ToolDecision(
        allowed=False,
        reason="Tool side-effect metadata requires review before execution.",
        mode="review",
        sanitized_args={key: value for key, value in args.items() if not str(key).startswith("_guardx_")},
        rule_id="side_effect_metadata.requires_review",
        evidence=[*analysis.labels, *analysis.evidence],
        constraints={
            "risk_score": analysis.risk_score,
            "surface": analysis.metadata.get("surface"),
            "benign_boundary": analysis.metadata.get("benign_boundary"),
        },
    )


def review_tool_call(tool_name: str, args: dict, session_risk: float) -> ToolDecision:
    policy = load_tool_policy()
    normalized = tool_name.strip().lower()
    if session_risk >= float(policy["high_session_risk_threshold"]):
        return high_session_risk_decision(session_risk, policy)
    side_effect_decision = side_effect_metadata_decision(normalized, args)
    if side_effect_decision is not None:
        return side_effect_decision
    if normalized == "read_file_safe":
        return review_read_file(args, policy)
    if normalized == "write_file_safe":
        return review_write_file(args, policy)
    if normalized == "http_get_safe":
        return review_http_get(args, policy)
    if normalized == "db_query_safe":
        return review_db_query(args, policy)
    if normalized == "shell_exec_sim":
        return review_shell_exec(args, policy)
    if normalized == "register_tool_safe":
        return review_register_tool(args, policy)
    if normalized == "agent_noop_safe":
        return review_agent_noop(args)
    return unknown_tool_decision(tool_name)
