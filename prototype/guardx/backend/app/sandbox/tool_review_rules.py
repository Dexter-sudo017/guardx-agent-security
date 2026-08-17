from typing import Any

from app.guards import output_guard
from app.models import ToolDecision
from app.sandbox.tool_policy import DEFAULT_POLICY, WRITE_CONTENT_KEYS
from app.sandbox.write_guard import (
    _looks_like_fragmented_sensitive_output,
    _path_has_workspace_write_allow_marker,
    _write_payload_should_block,
    _write_payload_text,
)


def _decision(
    allowed: bool,
    reason: str,
    mode: str,
    rule_id: str,
    *,
    sanitized_args: dict[str, Any] | None = None,
    evidence: list[str] | None = None,
    constraints: dict[str, Any] | None = None,
) -> ToolDecision:
    return ToolDecision(
        allowed=allowed,
        reason=reason,
        mode=mode,
        sanitized_args=sanitized_args or {},
        rule_id=rule_id,
        evidence=evidence or [reason],
        constraints=constraints or {},
    )


def high_session_risk_decision(session_risk: float, policy: dict) -> ToolDecision:
    return _decision(
        allowed=False,
        reason="High session risk. Tool disabled.",
        mode="deny",
        rule_id="session_risk.high",
        evidence=[f"session_risk={session_risk:.6f}"],
        constraints={"threshold": policy["high_session_risk_threshold"]},
    )


def review_read_file(args: dict, policy: dict) -> ToolDecision:
    path = str(args.get("path", "")).lower()
    read_denied = policy.get("read_denied_path_markers", policy["sensitive_path_markers"])
    if any(marker in path for marker in read_denied):
        return _decision(False, "Sensitive path access denied.", "deny", "file_read.sensitive_path", evidence=[path], constraints={"denied_markers": read_denied})
    return _decision(True, "Read-only file access allowed.", "read_only", "file_read.allowed", sanitized_args=args, evidence=[path])


def review_write_file(args: dict, policy: dict) -> ToolDecision:
    path = str(args.get("path", "")).lower()
    write_denied = policy.get("write_denied_path_markers", policy["sensitive_path_markers"])
    hard_denied = policy.get("write_hard_denied_path_markers", DEFAULT_POLICY["write_hard_denied_path_markers"])
    in_allowed_workspace_output = _path_has_workspace_write_allow_marker(path, policy)
    if any(marker in path for marker in hard_denied):
        return _decision(False, "Sensitive path write denied.", "deny", "file_write.hard_denied_path", evidence=[path], constraints={"hard_denied_markers": hard_denied})
    if any(marker in path for marker in write_denied) and not in_allowed_workspace_output:
        return _decision(False, "Sensitive path write denied.", "deny", "file_write.denied_path", evidence=[path], constraints={"denied_markers": write_denied})
    if not in_allowed_workspace_output:
        return _decision(
            False,
            "Workspace write outside allowed output paths denied.",
            "deny",
            "file_write.outside_allowed_workspace",
            evidence=[path],
            constraints={"allow_markers": policy.get("workspace_write_allow_markers", [])},
        )
    write_text = _write_payload_text(args)
    if write_text.strip():
        analysis = output_guard.analyze(write_text)
        if _write_payload_should_block(write_text, analysis):
            sanitized_args = dict(args)
            for key in WRITE_CONTENT_KEYS:
                value = sanitized_args.get(key)
                if isinstance(value, str):
                    sanitized_args[key] = output_guard.sanitize_text(value)
            return _decision(
                False,
                "Workspace write content contains sensitive output and was denied.",
                "redact_output",
                "file_write.sensitive_content",
                sanitized_args=sanitized_args,
                evidence=analysis.evidence,
                constraints={"output_labels": analysis.labels},
            )
    return _decision(True, "Workspace output write allowed.", "workspace_write", "file_write.workspace_output_allowed", sanitized_args=args, evidence=[path])


def review_http_get(args: dict, policy: dict) -> ToolDecision:
    domain = str(args.get("domain", "")).lower()
    if domain not in set(policy["allowed_domains"]):
        return _decision(False, "Domain not in allowlist.", "deny", "http_get.domain_not_allowed", evidence=[domain], constraints={"allowed_domains": policy["allowed_domains"]})
    return _decision(True, "Network call allowed to trusted domain.", "allow", "http_get.domain_allowed", sanitized_args=args, evidence=[domain])


def review_db_query(args: dict, policy: dict) -> ToolDecision:
    query = str(args.get("query", "")).lower()
    if any(marker in query for marker in policy["mutating_sql_markers"]):
        return _decision(False, "Mutating query denied.", "deny", "db_query.mutating_query", evidence=[query], constraints={"mutating_markers": policy["mutating_sql_markers"]})
    return _decision(True, "Read-only query allowed.", "read_only", "db_query.read_only", sanitized_args=args)


def review_shell_exec(args: dict, policy: dict) -> ToolDecision:
    command = str(args.get("command", "")).lower()
    shell_denied = policy.get("shell_denied_path_markers", policy["sensitive_path_markers"])
    if any(marker in command for marker in shell_denied):
        return _decision(False, "Sensitive path in shell command denied.", "deny", "shell.sensitive_path", evidence=[command], constraints={"denied_markers": shell_denied})
    if _looks_like_fragmented_sensitive_output(command):
        return _decision(False, "Fragmented sensitive output construction denied.", "deny", "shell.fragmented_sensitive_output", evidence=[command])
    if any(marker in command for marker in policy["dangerous_command_markers"]):
        return _decision(False, "Dangerous command pattern denied.", "deny", "shell.dangerous_command", evidence=[command], constraints={"dangerous_markers": policy["dangerous_command_markers"]})
    return _decision(True, "Simulated execution only.", "simulate", "shell.simulate_only", sanitized_args=args)


def review_register_tool(args: dict, policy: dict) -> ToolDecision:
    description = str(args.get("description", "")).lower()
    if any(marker in description for marker in policy["malicious_tool_description_markers"]):
        return _decision(False, "Tool description contains malicious instructions.", "deny", "tool_registration.malicious_description", evidence=[description], constraints={"malicious_markers": policy["malicious_tool_description_markers"]})
    constraints = args.get("constraints") if isinstance(args.get("constraints"), dict) else {}
    side_effects = args.get("side_effects")
    if isinstance(side_effects, str):
        side_effect_set = {side_effects.strip().lower()}
    elif isinstance(side_effects, list):
        side_effect_set = {str(item).strip().lower() for item in side_effects}
    else:
        side_effect_set = set()
    safe_side_effects = side_effect_set.issubset({"", "read", "none"})
    no_network_export = constraints.get("network_export") is False
    rollback_supported = constraints.get("rollback_supported") is True
    if safe_side_effects and no_network_export and rollback_supported:
        return _decision(
            True,
            "Tool manifest allowed with explicit provenance and side-effect boundary.",
            "allow_with_boundary",
            "tool_registration.safe_manifest_with_boundary",
            sanitized_args=args,
            evidence=["side_effects=read_or_none", "network_export=false", "rollback_supported=true"],
            constraints={"side_effects": sorted(side_effect_set), "network_export": False, "rollback_supported": True},
        )
    return _decision(True, "Tool registration allowed after description review.", "review", "tool_registration.reviewed", sanitized_args=args)


def review_agent_noop(args: dict) -> ToolDecision:
    return _decision(True, "Non-executing agent action allowed.", "allow", "agent.noop_allowed", sanitized_args=args)


def unknown_tool_decision(tool_name: str) -> ToolDecision:
    return _decision(False, f"Unknown tool `{tool_name}`.", "deny", "tool.unknown", evidence=[tool_name])
