from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from app.contracts import ExecutorCapability, ExecutorCapabilityManifest


PROJECT_ROOT = Path(__file__).resolve().parents[5]
CAPABILITY_PATH = PROJECT_ROOT / "configs" / "executor_capabilities.json"

DEFAULT_CAPABILITY_MANIFEST = {
    "schema_version": "guardx-executor-capabilities-v1",
    "default_runner": "simulated_safe_tool",
    "capabilities": [
        {
            "tool_name": "read_file_safe",
            "runner": "local_readonly_sandbox",
            "surfaces": ["agent_tool", "file", "file_read"],
            "side_effects": "read",
            "dry_run": False,
            "constraints": {"filesystem": "guardx_demo_sandbox_read_only"},
        },
        {
            "tool_name": "enterprise_search_safe",
            "runner": "enterprise_knowledge_search",
            "surfaces": ["agent_tool"],
            "side_effects": "read",
            "dry_run": False,
            "constraints": {"knowledge_base": "guardx_demo_read_only"},
        },
        {
            "tool_name": "create_review_ticket_safe",
            "runner": "controlled_review_ticket",
            "surfaces": ["agent_tool"],
            "side_effects": "write",
            "dry_run": False,
            "rollback_supported": True,
            "constraints": {"filesystem": "guardx_review_ticket_root", "approval_required": True},
        },
        {"tool_name": "write_file_safe", "surfaces": ["agent_tool"], "side_effects": "write", "dry_run": True, "rollback_supported": True},
        {"tool_name": "http_get_safe", "surfaces": ["agent_tool"], "side_effects": "network", "dry_run": True},
        {"tool_name": "db_query_safe", "surfaces": ["agent_tool"], "side_effects": "read", "dry_run": True},
        {"tool_name": "shell_exec_sim", "surfaces": ["agent_tool"], "side_effects": "compute", "dry_run": True},
        {"tool_name": "register_tool_safe", "surfaces": ["agent_tool"], "side_effects": "registration", "dry_run": True, "rollback_supported": True},
        {"tool_name": "agent_noop_safe", "surfaces": ["agent_tool"], "side_effects": "none", "dry_run": True},
    ],
}


def _load_manifest(path: Path) -> ExecutorCapabilityManifest:
    if not path.exists():
        return ExecutorCapabilityManifest.model_validate(DEFAULT_CAPABILITY_MANIFEST)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raw = DEFAULT_CAPABILITY_MANIFEST
    return ExecutorCapabilityManifest.model_validate(raw)


@lru_cache(maxsize=1)
def default_executor_capabilities() -> ExecutorCapabilityManifest:
    return _load_manifest(CAPABILITY_PATH)


def capability_for(tool_name: str, manifest: ExecutorCapabilityManifest | None = None) -> ExecutorCapability:
    active_manifest = manifest or default_executor_capabilities()
    normalized = tool_name.strip().lower()
    for capability in active_manifest.capabilities:
        if capability.tool_name.strip().lower() == normalized:
            return capability
    return ExecutorCapability(
        tool_name=normalized or "unknown_tool",
        runner=active_manifest.default_runner,
        side_effects="unknown",
        dry_run=True,
        rollback_supported=False,
        constraints={"known": False},
    )
