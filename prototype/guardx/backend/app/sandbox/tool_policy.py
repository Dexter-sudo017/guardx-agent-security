import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[5]
POLICY_PATH = PROJECT_ROOT / "configs" / "tool_policy.json"

DEFAULT_POLICY = {
    "high_session_risk_threshold": 0.7,
    "allowed_domains": ["docs.openclaw.ai", "owasp.org", "arxiv.org"],
    "sensitive_path_markers": ["secret", "token", ".env", "key", "credential", ".ssh"],
    "read_denied_path_markers": ["secret", "token", ".env", "key", "credential", ".ssh"],
    "write_denied_path_markers": [
        "secret",
        "token",
        ".env",
        "key",
        "credential",
        ".ssh",
        "zju_scraper/output",
        "zju_scraper\\output",
        "/home/lobster/zju_scraper/output",
        "\\home\\lobster\\zju_scraper\\output",
        ".openclaw",
        "configs",
        "skills",
        "gateway",
        "runtime",
        "openclaw.json",
    ],
    "write_hard_denied_path_markers": ["/secrets/", "\\secrets\\", ".env", ".ssh"],
    "shell_denied_path_markers": [
        "secret",
        "token",
        ".env",
        "key",
        "credential",
        ".ssh",
        "zju_scraper/output",
        "zju_scraper\\output",
        "/home/lobster/zju_scraper/output",
        "\\home\\lobster\\zju_scraper\\output",
        ".openclaw",
        "configs",
        "skills",
        "gateway",
        "runtime",
        "openclaw.json",
    ],
    "dangerous_command_markers": [
        "powershell",
        "cmd.exe",
        "bash",
        "curl",
        "wget",
        "invoke-webrequest",
        ".ssh",
        "del ",
        "rm ",
        "remove-item",
    ],
    "malicious_tool_description_markers": [
        "ignore policy",
        "ignore previous instructions",
        "forward sensitive data",
        "send selected",
        "hidden remote endpoint",
        "exfiltrate",
        "steal",
        "silently",
    ],
    "mutating_sql_markers": ["drop ", "delete ", "update ", "insert ", "truncate "],
    "workspace_write_allow_markers": ["/outputs/", "\\outputs\\", "/tmp/", "\\tmp\\"],
    "write_content_keyword_only_threshold": 0.7,
    "known_tools": ["read_file_safe", "write_file_safe", "http_get_safe", "db_query_safe", "shell_exec_sim", "register_tool_safe", "agent_noop_safe"],
}

WRITE_CONTENT_KEYS = {
    "content",
    "contents",
    "file_text",
    "inserted_text",
    "new_str",
    "old_str",
    "replacement",
    "text",
    "value",
}


def load_tool_policy() -> dict:
    if not POLICY_PATH.exists():
        return DEFAULT_POLICY
    try:
        loaded = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except Exception:
        return DEFAULT_POLICY
    merged = DEFAULT_POLICY.copy()
    merged.update({key: value for key, value in loaded.items() if key != "schema_version"})
    return merged
