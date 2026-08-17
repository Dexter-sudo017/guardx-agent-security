from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


BACKEND_ROOT = Path(__file__).resolve().parents[2]
EXPERIMENT_RUNS_DIR = BACKEND_ROOT / "data" / "experiment_runs"
DEFAULT_PREFLIGHT = EXPERIMENT_RUNS_DIR / "latest_live_target_preflight.json"
DEFAULT_REHEARSAL = EXPERIMENT_RUNS_DIR / "latest_live_target_rehearsal.json"
SCHEMA_VERSION = "guardx-live-target-readiness-v1"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _case_counts(profiles: list[dict[str, Any]]) -> dict[str, int]:
    cases = [case for profile in profiles for case in profile.get("cases", []) if isinstance(case, dict)]
    passed = [case for case in cases if case.get("passed") is True]
    forwarded = [case for case in passed if case.get("target_called") is True]
    suppressed = [case for case in passed if case.get("target_called") is False]
    return {
        "case_count": len(cases),
        "validated_case_count": len(passed),
        "forwarded_case_count": len(forwarded),
        "suppressed_case_count": len(suppressed),
    }


def _profile_states(profiles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "profile_id": profile.get("profile_id"),
            "ready": profile.get("ready") is True,
            "skipped": profile.get("skipped") is True,
            "case_count": int(profile.get("case_count") or 0),
            "failed_case_count": int(profile.get("failed_case_count") or 0),
        }
        for profile in profiles
        if isinstance(profile, dict)
    ]


def _blockers(preflight: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for blocker in preflight.get("blockers") or []:
        if not isinstance(blocker, dict):
            continue
        result.append(
            {
                "profile_id": blocker.get("profile_id"),
                "reason": blocker.get("reason"),
                "missing_env": blocker.get("missing_env") or [],
            }
        )
    return result


def build_live_target_readiness(
    *,
    run_id: str = "local-live-target-readiness",
    preflight_path: Path = DEFAULT_PREFLIGHT,
    rehearsal_path: Path = DEFAULT_REHEARSAL,
) -> dict[str, Any]:
    preflight = _load_json(preflight_path)
    rehearsal = _load_json(rehearsal_path)
    profiles = rehearsal.get("profiles") if isinstance(rehearsal.get("profiles"), list) else []
    counts = _case_counts(profiles)
    blockers = _blockers(preflight)
    preflight_available = bool(preflight)
    rehearsal_available = bool(rehearsal)
    ready = preflight_available and rehearsal.get("ready") is True and counts["validated_case_count"] > 0
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "created_at": datetime.now(UTC).isoformat(),
        "ready": ready,
        "available": {"preflight": preflight_available, "rehearsal": rehearsal_available},
        "source_runs": {"preflight": preflight.get("run_id"), "rehearsal": rehearsal.get("run_id")},
        "requested_profiles": rehearsal.get("requested_profiles") or preflight.get("requested_profiles") or [],
        "required_profiles": rehearsal.get("required_profiles") or [],
        "skipped_profile_count": int(rehearsal.get("skipped_profile_count") or 0),
        "failed_profile_count": int(rehearsal.get("failed_profile_count") or 0),
        "required_profile_failure_count": int(rehearsal.get("required_profile_failure_count") or 0),
        "external_blocker_count": len(blockers),
        "external_blockers": blockers,
        "profile_states": _profile_states(profiles),
        **counts,
        "judge_summary": (
            f"{counts['validated_case_count']} live/local cases validated; "
            f"{counts['forwarded_case_count']} forwarded and {counts['suppressed_case_count']} suppressed; "
            f"{len(blockers)} optional live target blockers are visible."
        ),
    }
