from uuid import uuid4

from app.contracts.audit import ExperimentModelMatrixResponse, ExperimentSuiteRunResponse
from app.services.experiment_runner import run_builtin_experiment_suite


def _safe_model_id(model: str) -> str:
    return "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in model)[:64] or "model"


def _comparison_rows(runs: list[dict]) -> list[dict]:
    rows: dict[str, dict] = {}
    for run in runs:
        model = str(run.get("model", "unknown"))
        for case in run.get("cases", []):
            case_id = str(case.get("case_id", "unknown"))
            row = rows.setdefault(case_id, {"case_id": case_id, "surface": case.get("surface"), "models": {}})
            row["models"][model] = {
                "route": case.get("route"),
                "action": case.get("action"),
                "risk_score": case.get("risk_score"),
                "raw_risk_score": case.get("raw_risk_score"),
                "output_preview": case.get("output_preview", ""),
            }
    for row in rows.values():
        cells = list(row["models"].values())
        risks = [float(cell.get("risk_score") or 0.0) for cell in cells]
        row["diff"] = {
            "route_variants": sorted({str(cell.get("route")) for cell in cells}),
            "action_variants": sorted({str(cell.get("action")) for cell in cells}),
            "risk_min": min(risks) if risks else 0.0,
            "risk_max": max(risks) if risks else 0.0,
            "risk_range": (max(risks) - min(risks)) if risks else 0.0,
            "output_variants": len({str(cell.get("output_preview", "")) for cell in cells}),
        }
    return [rows[key] for key in sorted(rows)]


def run_model_matrix(
    *,
    suite_id: str,
    policy_profile: str,
    models: list[str],
    base_session_id: str | None = None,
    seed: int = 77,
) -> dict:
    active_models = [model.strip() for model in models if model.strip()]
    if not active_models:
        active_models = ["mock-safe-model"]
    base_session = base_session_id or f"{suite_id}-matrix-{uuid4().hex[:8]}"
    runs = [
        run_builtin_experiment_suite(
            suite_id=suite_id,
            policy_profile=policy_profile,
            session_id=f"{base_session}-{_safe_model_id(model)}",
            model=model,
            seed=seed,
        )
        for model in active_models
    ]
    response = ExperimentModelMatrixResponse(
        suite_id=suite_id,
        policy_profile=policy_profile,
        base_session_id=base_session,
        models=active_models,
        runs=[ExperimentSuiteRunResponse(**run) for run in runs],
        comparison=_comparison_rows(runs),
    )
    return response.model_dump()
