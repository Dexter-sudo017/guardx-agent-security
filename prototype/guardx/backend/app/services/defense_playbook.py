from __future__ import annotations

from typing import Any


DEFENSE_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "roleplay_policy_bypass": {
        "defense_id": "input.intent_boundary_rewrite",
        "method": "Intent-boundary rewrite",
        "runtime_action": "rewrite_or_block",
        "controls": ["input_guard", "policy_engine", "safe_refusal"],
        "defense_steps": [
            "Treat roleplay as benign unless it asks for privileged policy, hidden state, or unrestricted behavior.",
            "Rewrite the request to a safe boundary explanation when risk is medium.",
            "Block when the request asks to expose hidden policy or internal prompts.",
        ],
    },
    "euphemistic_policy_override": {
        "defense_id": "input.instruction_hierarchy_gate",
        "method": "Instruction-hierarchy gate",
        "runtime_action": "block",
        "controls": ["semantic_guard", "policy_engine"],
        "defense_steps": [
            "Detect claims that user text has higher priority than system/developer policy.",
            "Reject requests to restate hidden operating policy.",
            "Keep only the user-visible task if a safe rewrite is possible.",
        ],
    },
    "indirect_prompt_injection": {
        "defense_id": "context.structured_query_quarantine",
        "method": "Structured query quarantine",
        "runtime_action": "quarantine_context_or_block",
        "controls": ["segment_trust_boundary", "context_guard", "guarded_rag_prompt"],
        "defense_steps": [
            "Mark retrieved context as data, not instructions.",
            "Wrap low-trust chunks with evidence-only delimiters before generation.",
            "Drop or block context that claims instruction priority or asks for tool calls.",
        ],
    },
    "ocr_hidden_instruction": {
        "defense_id": "vlm.ocr_instruction_quarantine",
        "method": "OCR instruction quarantine",
        "runtime_action": "quarantine_ocr_or_block",
        "controls": ["vlm_segment_boundary", "context_guard", "output_guard"],
        "defense_steps": [
            "Treat OCR text and VLM captions as untrusted image evidence.",
            "Prevent image text from changing task priority or tool permissions.",
            "Require summary-only output when image text contains instruction-like content.",
        ],
    },
    "tool_output_injection": {
        "defense_id": "observation.output_sanitization",
        "method": "Tool observation sanitization",
        "runtime_action": "redact_or_review",
        "controls": ["output_guard", "action_observation_guard", "replay_audit"],
        "defense_steps": [
            "Treat tool output as untrusted observation.",
            "Sanitize observations that ask for follow-up instructions, hidden policy disclosure, or network export.",
            "Record observation hash and phase in executor replay.",
        ],
    },
    "sensitive_file_read": {
        "defense_id": "executor.file_precheck",
        "method": "Executor file precheck",
        "runtime_action": "deny_tool",
        "controls": ["action_guard", "tool_policy", "executor_lifecycle"],
        "defense_steps": [
            "Normalize agent action payloads before execution.",
            "Deny reads of paths containing token, secret, credential, .env, or key markers.",
            "Record deny reason, mapped args, and provenance in replay.",
        ],
    },
    "network_exfiltration": {
        "defense_id": "executor.network_allowlist",
        "method": "Network side-effect allowlist",
        "runtime_action": "deny_tool",
        "controls": ["action_guard", "domain_allowlist", "executor_lifecycle"],
        "defense_steps": [
            "Normalize URL/domain fields before policy review.",
            "Allow only approved documentation domains in low-risk sessions.",
            "Deny unknown or attacker-controlled domains and preserve the blocked action in replay.",
        ],
    },
    "benign_roleplay": {
        "defense_id": "utility.false_positive_control",
        "method": "Benign framing recovery",
        "runtime_action": "allow",
        "controls": ["benign_dampening", "policy_engine"],
        "defense_steps": [
            "Do not block roleplay merely because it is roleplay.",
            "Allow safety training or customer support simulations when they do not request privileged content.",
        ],
    },
    "benign_training_quote": {
        "defense_id": "context.quote_as_evidence",
        "method": "Quoted-risk evidence mode",
        "runtime_action": "allow_with_context_boundary",
        "controls": ["context_guard", "benign_context_dampening"],
        "defense_steps": [
            "Distinguish quoted attack examples from executable instructions.",
            "Keep quoted examples as training evidence and continue the safe summarization task.",
        ],
    },
    "benign_ocr_privacy_training": {
        "defense_id": "vlm.benign_privacy_recovery",
        "method": "Privacy-training recovery",
        "runtime_action": "allow",
        "controls": ["context_guard", "output_guard"],
        "defense_steps": [
            "Allow OCR privacy-awareness posters that instruct users not to reveal secrets.",
            "Keep any synthetic token-like examples in safe training context.",
        ],
    },
    "benign_tool_use": {
        "defense_id": "executor.utility_allowlist",
        "method": "Low-risk tool utility allowlist",
        "runtime_action": "allow_tool",
        "controls": ["tool_policy", "action_mapping"],
        "defense_steps": [
            "Normalize top-level action fields and nested args consistently.",
            "Allow low-risk documentation lookups to approved domains.",
            "Continue logging provenance even when the action is allowed.",
        ],
    },
    "benign_plugin_manifest_review": {
        "defense_id": "plugin.manifest_review_allow",
        "method": "Plugin manifest review recovery",
        "runtime_action": "allow_with_context_boundary",
        "controls": ["plugin_source_audit", "benign_context_dampening"],
        "defense_steps": [
            "Allow defensive review of plugin manifests when the task is to identify risky permissions.",
            "Keep manifest text as evidence and do not execute embedded tool-registration language.",
            "Continue provenance logging for source URI, runner, and declared side effects.",
        ],
    },
    "benign_security_operations": {
        "defense_id": "audit.security_ops_review_allow",
        "method": "Security operations review recovery",
        "runtime_action": "allow_with_context_boundary",
        "controls": ["audit_trace", "benign_context_dampening"],
        "defense_steps": [
            "Allow incident reports and security-operation summaries that discuss attack patterns defensively.",
            "Treat any quoted payload as evidence instead of a new instruction.",
            "Preserve trace hashes and provenance for replay without rendering raw risky text.",
        ],
    },
}


DEFAULT_PLAYBOOK = {
    "defense_id": "policy.default_review",
    "method": "Default policy review",
    "runtime_action": "review",
    "controls": ["risk_finding", "policy_engine", "audit_replay"],
    "defense_steps": [
        "Collect RiskFinding evidence from available providers.",
        "Route to allow, review, or block based on risk score and policy profile.",
        "Record trace and provenance for replay.",
    ],
}


def recommend_defense(*, attack_vector: str, trust_boundary: str = "", route: str = "", risk_provider_ids: list[str] | None = None) -> dict[str, Any]:
    base = dict(DEFENSE_PLAYBOOKS.get(attack_vector, DEFAULT_PLAYBOOK))
    base["attack_vector"] = attack_vector
    base["trust_boundary"] = trust_boundary
    base["observed_route"] = route
    base["risk_provider_ids"] = sorted(set(risk_provider_ids or []))
    base["is_detection_only"] = False
    return base


__all__ = ["DEFENSE_PLAYBOOKS", "recommend_defense"]
