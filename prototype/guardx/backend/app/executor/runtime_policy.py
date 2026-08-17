from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from app.contracts import ExecutorRuntimePolicy, ExecutorRuntimePolicyManifest


PROJECT_ROOT = Path(__file__).resolve().parents[5]
RUNTIME_POLICY_PATH = PROJECT_ROOT / "configs" / "executor_runtime_policy.json"

DEFAULT_RUNTIME_POLICY = {
    "schema_version": "guardx-executor-runtime-policy-v1",
    "default_policy": {
        "execution_timeout_ms": 10000,
        "max_retries": 0,
        "retry_backoff_ms": 0,
        "rollback_on_failure": True,
        "rollback_timeout_ms": 5000,
    },
    "tools": {},
}


def _load_manifest(path: Path) -> ExecutorRuntimePolicyManifest:
    if not path.exists():
        return ExecutorRuntimePolicyManifest.model_validate(DEFAULT_RUNTIME_POLICY)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raw = DEFAULT_RUNTIME_POLICY
    return ExecutorRuntimePolicyManifest.model_validate(raw)


@lru_cache(maxsize=1)
def default_executor_runtime_policy() -> ExecutorRuntimePolicyManifest:
    return _load_manifest(RUNTIME_POLICY_PATH)


def runtime_policy_for(tool_name: str, manifest: ExecutorRuntimePolicyManifest | None = None) -> ExecutorRuntimePolicy:
    active_manifest = manifest or default_executor_runtime_policy()
    normalized = tool_name.strip().lower()
    return active_manifest.tools.get(normalized, active_manifest.default_policy)
