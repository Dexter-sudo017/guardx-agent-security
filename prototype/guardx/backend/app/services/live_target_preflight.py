from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.error import URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import urlopen

from app.services.runtime_state import adapter_registry


SCHEMA_VERSION = "guardx-live-target-preflight-v1"
PROFILE_IDS = {
    "local": "local_http_rag_target",
    "ollama": "local_ollama",
    "docker": "docker_runtime",
    "anythingllm": "anythingllm",
    "openhands": "openhands_action_proxy",
}


CommandRunner = Callable[[list[str]], tuple[bool, str]]
HttpProbe = Callable[[str], tuple[bool, str]]


def _run_command(command: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    output = (result.stdout or result.stderr or "").strip().splitlines()
    return result.returncode == 0, (output[0] if output else "")


def _http_get_ok(url: str) -> tuple[bool, str]:
    try:
        with urlopen(url, timeout=3) as response:
            return 200 <= response.status < 300, f"http_{response.status}"
    except (OSError, URLError) as exc:
        return False, str(exc)


def _openhands_alive_url(action_proxy_url: str) -> str:
    parts = urlsplit(action_proxy_url)
    if not parts.scheme or not parts.netloc:
        return ""
    return urlunsplit((parts.scheme, parts.netloc, "/alive", "", ""))


def _check(profile_id: str, ready: bool, reason: str, *, details: dict[str, Any] | None = None, missing_env: list[str] | None = None) -> dict[str, Any]:
    return {
        "profile_id": profile_id,
        "ready": ready,
        "reason": reason,
        "missing_env": missing_env or [],
        "details": details or {},
    }


def _local_check() -> dict[str, Any]:
    return _check("local_http_rag_target", True, "local_replay_target_starts_in_process")


def _ollama_check(model: str, env: Mapping[str, str]) -> dict[str, Any]:
    info = adapter_registry.get_info(model)
    ready = bool(getattr(info, "configured", False))
    missing = [] if ready or env.get("OLLAMA_BASE_URL") else ["OLLAMA_BASE_URL"]
    reason = "ollama_adapter_configured" if ready else "ollama_adapter_not_configured_or_unreachable"
    return _check("local_ollama", ready, reason, details={"model": model}, missing_env=missing)


def _docker_check(command_runner: CommandRunner) -> dict[str, Any]:
    if shutil.which("docker") is None:
        return _check("docker_runtime", False, "docker_cli_not_found")
    version_ok, version = command_runner(["docker", "--version"])
    daemon_ok, daemon = command_runner(["docker", "ps"])
    ready = version_ok and daemon_ok
    reason = "docker_cli_and_daemon_ready" if ready else "docker_daemon_unavailable"
    return _check("docker_runtime", ready, reason, details={"version": version, "daemon_probe": daemon})


def _anythingllm_check(env: Mapping[str, str]) -> dict[str, Any]:
    missing = [name for name in ["ANYTHINGLLM_API_KEY"] if not env.get(name)]
    ready = not missing
    reason = "anythingllm_api_key_configured" if ready else "missing_anythingllm_api_key"
    return _check("anythingllm", ready, reason, missing_env=missing)


def _openhands_check(env: Mapping[str, str], http_probe: HttpProbe) -> dict[str, Any]:
    action_proxy_url = env.get("GUARDX_OPENHANDS_ACTION_PROXY_URL", "").strip()
    missing = [name for name in ["GUARDX_OPENHANDS_ACTION_PROXY_URL"] if not action_proxy_url]
    if missing:
        return _check("openhands_action_proxy", False, "missing_openhands_action_proxy_url", missing_env=missing)
    alive_url = _openhands_alive_url(action_proxy_url)
    if not alive_url:
        return _check("openhands_action_proxy", False, "invalid_openhands_action_proxy_url", details={"action_proxy_url_configured": True})
    alive_ok, alive_detail = http_probe(alive_url)
    reason = "openhands_proxy_alive" if alive_ok else "openhands_proxy_unreachable"
    return _check("openhands_action_proxy", alive_ok, reason, details={"alive_url": alive_url, "alive_probe": alive_detail})



def build_live_target_preflight(
    *,
    run_id: str,
    profiles: list[str],
    required_profiles: list[str] | None = None,
    ollama_model: str = "local-ollama-qwen2_5-coder-1_5b",
    env: Mapping[str, str] | None = None,
    command_runner: CommandRunner = _run_command,
    http_probe: HttpProbe = _http_get_ok,
) -> dict[str, Any]:
    env_map = env or os.environ
    selected = {item.strip().lower() for item in profiles if item.strip()}
    required_ids = {PROFILE_IDS.get(item.strip().lower(), item.strip().lower()) for item in (required_profiles or []) if item.strip()}
    checks: list[dict[str, Any]] = []
    if "local" in selected:
        checks.append(_local_check())
    if "ollama" in selected:
        checks.append(_ollama_check(ollama_model, env_map))
    if "docker" in selected:
        checks.append(_docker_check(command_runner))
    if "anythingllm" in selected:
        checks.append(_anythingllm_check(env_map))
    if "openhands" in selected:
        checks.append(_openhands_check(env_map, http_probe))
    required_failures = [item for item in checks if item["profile_id"] in required_ids and not item["ready"]]
    blockers = [item for item in checks if not item["ready"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "created_at": datetime.now(UTC).isoformat(),
        "requested_profiles": sorted(selected),
        "required_profiles": sorted(required_ids),
        "ready": bool(checks) and not required_failures,
        "check_count": len(checks),
        "blocker_count": len(blockers),
        "required_failure_count": len(required_failures),
        "blockers": blockers,
        "checks": checks,
    }
