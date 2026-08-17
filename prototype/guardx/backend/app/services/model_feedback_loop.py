from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.services import experiment_artifact_index


SCHEMA_VERSION = "guardx-model-feedback-loop-v1"


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if data.get("schema_version") == "guardx-model-matrix-summary-v2" else None


def _summary_files(limit: int = 120) -> list[Path]:
    root = experiment_artifact_index.EXPERIMENT_RUNS_DIR
    if not root.exists():
        return []
    paths = [
        path
        for path in root.iterdir()
        if path.is_file() and path.suffix == ".json" and ("summary" in path.name or "matrix" in path.name)
    ]
    return sorted(paths, key=lambda item: (item.stat().st_mtime, item.name))[-limit:]


def _task_key(suite_id: str, failure: dict[str, Any]) -> str:
    return f"{suite_id}::{failure.get('case_id') or 'unknown'}::{failure.get('reason') or 'route_mismatch'}"


def _action_for_failure(failure: dict[str, Any]) -> str:
    case_id = str(failure.get("case_id") or "")
    reason = str(failure.get("reason") or "")
    if "secret_redaction" in case_id:
        return "Tune secret-handling policy and verify real secret markers remain high risk."
    if "rag" in case_id or "training" in case_id:
        return "Pass trusted context into output analysis and verify benign training summaries."
    if reason == "no_final_or_unavailable":
        return "Inspect adapter output health and fallback behavior for empty or unavailable responses."
    return "Review policy threshold, evidence, and expected route for this case."


def _failures_by_suite(summary: dict[str, Any]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    result: dict[str, dict[str, list[dict[str, Any]]]] = {}
    suites = summary.get("suites") if isinstance(summary.get("suites"), dict) else {}
    for suite_id, suite in suites.items():
        models = suite.get("models") if isinstance(suite, dict) else {}
        if not isinstance(models, dict):
            continue
        result[str(suite_id)] = {}
        for model, metrics in models.items():
            failures = metrics.get("failures") if isinstance(metrics, dict) else []
            result[str(suite_id)][str(model)] = list(failures or [])
    return result


def _register_failure(tasks: dict[str, dict[str, Any]], suite_id: str, model: str, failure: dict[str, Any], run_id: str, path: Path) -> None:
    key = _task_key(suite_id, failure)
    task = tasks.setdefault(
        key,
        {
            "task_id": key,
            "suite_id": suite_id,
            "case_id": failure.get("case_id"),
            "reason": failure.get("reason") or "route_mismatch",
            "expected_routes": failure.get("expected_routes") or [],
            "affected_models": [],
            "first_seen_run": run_id,
            "last_seen_run": run_id,
            "source_artifacts": [],
            "status": "open",
            "action": _action_for_failure(failure),
        },
    )
    if model not in task["affected_models"]:
        task["affected_models"].append(model)
    if path.name not in task["source_artifacts"]:
        task["source_artifacts"].append(path.name)
    task["last_seen_run"] = run_id
    task["status"] = "open"
    task.pop("resolved_by_run", None)


def build_model_feedback_loop(*, run_id: str = "local-feedback-loop", limit: int = 120) -> dict[str, Any]:
    tasks: dict[str, dict[str, Any]] = {}
    processed: list[str] = []
    for path in _summary_files(limit=limit):
        summary = _load_json(path)
        if not summary:
            continue
        processed.append(path.name)
        current_run = str(summary.get("run_id") or path.stem)
        suite_failures = _failures_by_suite(summary)
        for suite_id, model_failures in suite_failures.items():
            active_keys = {
                _task_key(suite_id, failure)
                for failures in model_failures.values()
                for failure in failures
            }
            for task in tasks.values():
                if task["suite_id"] == suite_id and task["status"] == "open" and task["task_id"] not in active_keys:
                    task["status"] = "resolved"
                    task["resolved_by_run"] = current_run
            for model, failures in model_failures.items():
                for failure in failures:
                    _register_failure(tasks, suite_id, model, failure, current_run, path)
    ordered = sorted(tasks.values(), key=lambda item: (item["status"], item["suite_id"], str(item["case_id"])))
    open_tasks = [task for task in ordered if task["status"] == "open"]
    resolved_tasks = [task for task in ordered if task["status"] == "resolved"]
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "created_at": datetime.now(UTC).isoformat(),
        "processed_artifacts": processed,
        "open_task_count": len(open_tasks),
        "resolved_task_count": len(resolved_tasks),
        "open_tasks": open_tasks,
        "resolved_tasks": resolved_tasks,
    }
