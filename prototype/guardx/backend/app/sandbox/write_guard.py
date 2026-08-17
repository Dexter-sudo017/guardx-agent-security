from app.guards import output_guard
from app.sandbox.tool_policy import DEFAULT_POLICY, WRITE_CONTENT_KEYS, load_tool_policy


def _collect_write_payload_text(value, *, key_hint: str = "") -> list[str]:
    if isinstance(value, str):
        return [value] if key_hint in WRITE_CONTENT_KEYS else []
    if isinstance(value, list):
        collected: list[str] = []
        for item in value:
            collected.extend(_collect_write_payload_text(item, key_hint=key_hint))
        return collected
    if isinstance(value, dict):
        collected = []
        for key, nested in value.items():
            key_l = str(key).strip().lower()
            if key_l in {"command", "dir_path", "file_path", "path"}:
                continue
            collected.extend(_collect_write_payload_text(nested, key_hint=key_l))
        return collected
    return []


def _write_payload_text(args: dict) -> str:
    return "\n".join(_collect_write_payload_text(args))


def _looks_like_fragmented_sensitive_output(text: str) -> bool:
    lowered = text.lower()
    has_write_sink = any(
        marker in lowered
        for marker in (
            " > ",
            ">>",
            ".write(",
            "set-content",
            "out-file",
            "tee ",
            "add-content",
        )
    )
    if not has_write_sink:
        return False
    compact = "".join(ch for ch in lowered if ch.isalnum())
    synthetic_fragments = "gx" in compact and "synth" in compact and "sec" in compact and "ret" in compact
    credential_fragments = (
        ("api" in compact and "key" in compact)
        or ("private" in compact and "token" in compact)
        or ("secret" in compact)
    )
    return synthetic_fragments or credential_fragments


def _path_has_workspace_write_allow_marker(path: str, policy: dict) -> bool:
    allow_markers = policy.get("workspace_write_allow_markers", DEFAULT_POLICY["workspace_write_allow_markers"])
    return bool(allow_markers and any(marker in path for marker in allow_markers))


def _looks_like_benign_security_write_prose(text: str) -> bool:
    lowered = text.lower()
    context_markers = (
        "security training",
        "documentation",
        "guidance",
        "policy",
        "rotation",
        "storage",
        "redaction",
        "credential management",
        "secret management",
        "no credential value",
        "does not include",
    )
    action_markers = (
        "copy",
        "copied from",
        "capture proof",
        "exfiltrate",
        "send to",
        "forward",
        "leak",
        "dump",
    )
    return any(marker in lowered for marker in context_markers) and not any(marker in lowered for marker in action_markers)


def _write_payload_has_fragmented_credential_value(text: str) -> bool:
    lowered = text.lower()
    compact = "".join(ch for ch in lowered if ch.isalnum())
    synthetic_key_fragments = "sk" in compact and "synthetic" in compact and "canary" in compact
    rb016_probe_fragments = "sk" in compact and "rb016" in compact and "synthetic" in compact
    generic_key_fragments = "api" in compact and "key" in compact and "prefix" in compact and "suffix" in compact and "sk" in compact
    return synthetic_key_fragments or rb016_probe_fragments or generic_key_fragments


def _write_payload_should_block(text: str, analysis) -> bool:
    output_policy = output_guard.load_output_policy()
    regex_evidence = set(output_policy.get("leak_regex_patterns", []))
    if any(item in regex_evidence for item in analysis.evidence):
        return True
    if _write_payload_has_fragmented_credential_value(text):
        return True
    if _looks_like_benign_security_write_prose(text):
        return False
    threshold = float(load_tool_policy().get("write_content_keyword_only_threshold", DEFAULT_POLICY["write_content_keyword_only_threshold"]))
    return analysis.risk_score >= threshold
