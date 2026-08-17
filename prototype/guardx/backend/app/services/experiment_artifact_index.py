import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.audit.experiment_artifact_metadata import artifact_kind, load_json_metadata
from app.services.admin_runtime import PROJECT_ROOT, STATIC_MATRIX_DASHBOARD


DEFAULT_EXPERIMENT_RUNS_DIR = STATIC_MATRIX_DASHBOARD.parent
EXPERIMENT_RUNS_DIR = DEFAULT_EXPERIMENT_RUNS_DIR
EVIDENCE_ARTIFACT_DIR = PROJECT_ROOT / "evidence"
LATEST_REAL_MODEL_GATE = EXPERIMENT_RUNS_DIR / "latest_real_model_gate.json"


def _modified_at(path: Path) -> str | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat()
    except OSError:
        return None


def _current_gate_status(path: Path, gate: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    recommended = gate.get("recommended_models") if isinstance(gate.get("recommended_models"), list) else []
    promoted = gate.get("promoted_models") if isinstance(gate.get("promoted_models"), list) else []
    stable = gate.get("stable_models") if isinstance(gate.get("stable_models"), list) else []
    demoted = gate.get("demoted_models") if isinstance(gate.get("demoted_models"), list) else []
    excluded = gate.get("excluded_models") if isinstance(gate.get("excluded_models"), list) else []
    thresholds = gate.get("thresholds") if isinstance(gate.get("thresholds"), dict) else metadata.get("thresholds", {})
    return {
        "state": "ready" if recommended else "no_recommendation",
        "run_id": gate.get("run_id") or metadata.get("run_id"),
        "policy_profile": gate.get("policy_profile") or metadata.get("policy_profile"),
        "created_at": gate.get("created_at"),
        "modified_at": _modified_at(path),
        "source_summary_artifact": gate.get("summary_artifact"),
        "previous_gate_artifact": gate.get("previous_gate_artifact"),
        "recommended_count": len(recommended),
        "promoted_count": len(promoted),
        "stable_count": len(stable),
        "demoted_count": len(demoted),
        "excluded_count": len(excluded),
        "thresholds": thresholds,
    }


def list_experiment_artifacts(limit: int = 50, kind: str | None = None) -> dict[str, Any]:
    limit = max(1, min(limit, 1000))
    kind_filter = kind.strip() if kind else None
    artifacts = []
    seen_paths: set[str] = set()
    source_dirs = [EXPERIMENT_RUNS_DIR]
    if EXPERIMENT_RUNS_DIR == DEFAULT_EXPERIMENT_RUNS_DIR and EVIDENCE_ARTIFACT_DIR.exists():
        source_dirs.append(EVIDENCE_ARTIFACT_DIR)
    candidates: list[tuple[float, Path, Any]] = []
    for source_dir in source_dirs:
        if not source_dir.exists():
            continue
        for path in source_dir.iterdir():
            if not path.is_file() or path.suffix.lower() not in {".json", ".html"}:
                continue
            resolved = path.resolve().as_posix()
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)
            stat = path.stat()
            candidates.append((stat.st_mtime, path, stat))
    for _, path, stat in sorted(candidates, key=lambda item: item[0], reverse=True):
        metadata = load_json_metadata(path) if path.suffix.lower() == ".json" else {}
        current_kind = artifact_kind(path, metadata)
        if kind_filter and current_kind != kind_filter:
            continue
        artifacts.append(
            {
                "name": path.name,
                "kind": current_kind,
                "path": path.as_posix(),
                "size_bytes": stat.st_size,
                "modified_at": stat.st_mtime,
                "metadata": metadata,
            }
        )
        if len(artifacts) >= limit:
            return {
                "schema_version": "guardx-experiment-artifact-index-v1",
                "data_dir": EXPERIMENT_RUNS_DIR.as_posix(),
                "evidence_dir": EVIDENCE_ARTIFACT_DIR.as_posix(),
                "latest_dashboard": STATIC_MATRIX_DASHBOARD.as_posix(),
                "kind_filter": kind_filter,
                "artifacts": artifacts,
            }
    return {
        "schema_version": "guardx-experiment-artifact-index-v1",
        "data_dir": EXPERIMENT_RUNS_DIR.as_posix(),
        "evidence_dir": EVIDENCE_ARTIFACT_DIR.as_posix(),
        "latest_dashboard": STATIC_MATRIX_DASHBOARD.as_posix(),
        "kind_filter": kind_filter,
        "artifacts": artifacts,
    }


def current_model_recommendation_gate() -> dict[str, Any]:
    path = LATEST_REAL_MODEL_GATE
    if not path.exists():
        return {
            "schema_version": "guardx-current-model-recommendation-gate-v1",
            "available": False,
            "path": path.as_posix(),
            "status": {"state": "missing", "expected_path": path.as_posix()},
            "gate": None,
        }
    try:
        gate = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "schema_version": "guardx-current-model-recommendation-gate-v1",
            "available": False,
            "path": path.as_posix(),
            "error": str(exc),
            "status": {"state": "invalid", "expected_path": path.as_posix()},
            "gate": None,
        }
    metadata = load_json_metadata(path)
    return {
        "schema_version": "guardx-current-model-recommendation-gate-v1",
        "available": True,
        "path": path.as_posix(),
        "metadata": metadata,
        "status": _current_gate_status(path, gate, metadata),
        "gate": gate,
    }
