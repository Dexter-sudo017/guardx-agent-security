from uuid import uuid4

from app.contracts import ExperimentStabilityResponse
from app.services.experiment_model_matrix import run_model_matrix
from app.services.experiment_suite_registry import experiment_suite_cases


def _case_contracts(suite_id: str) -> dict[str, dict]:
    return {
        case.case_id: {
            "surface": case.kind,
            "expectation": case.expectation,
            "expected_routes": list(case.expected_routes),
        }
        for case in experiment_suite_cases(suite_id)
    }


def _case_results_by_model(matrix: dict, model: str) -> list[dict]:
    for run in matrix.get("runs", []):
        if run.get("model") == model:
            return list(run.get("cases", []))
    return []


def _missing_output(case: dict) -> bool:
    action = str(case.get("action", ""))
    route = str(case.get("route", ""))
    if route == "block" or action == "terminate":
        return False
    return not str(case.get("output_preview", "")).strip()


def _summarize_model(model: str, rounds: list[dict], contracts: dict[str, dict]) -> dict:
    route_by_case: dict[str, list[str]] = {}
    risks_by_case: dict[str, list[float]] = {}
    failures: list[dict] = []
    empty_outputs = 0
    total_cases = 0
    route_counts: dict[str, int] = {}
    for round_index, matrix in enumerate(rounds, start=1):
        for case in _case_results_by_model(matrix, model):
            case_id = str(case.get("case_id", "unknown"))
            route = str(case.get("route", "unknown"))
            risk = float(case.get("risk_score") or 0.0)
            contract = contracts.get(case_id, {})
            expected_routes = list(contract.get("expected_routes", []))
            total_cases += 1
            route_counts[route] = route_counts.get(route, 0) + 1
            route_by_case.setdefault(case_id, []).append(route)
            risks_by_case.setdefault(case_id, []).append(risk)
            if expected_routes and route not in expected_routes:
                failures.append({"round": round_index, "case_id": case_id, "route": route, "expected_routes": expected_routes})
            if _missing_output(case):
                empty_outputs += 1
                failures.append({"round": round_index, "case_id": case_id, "route": route, "reason": "empty_output"})
    route_variants = {case_id: sorted(set(routes)) for case_id, routes in route_by_case.items()}
    unstable_cases = [case_id for case_id, variants in route_variants.items() if len(variants) > 1]
    risk_ranges = {
        case_id: {
            "min": min(risks),
            "max": max(risks),
            "range": max(risks) - min(risks),
        }
        for case_id, risks in risks_by_case.items()
        if risks
    }
    expected_ok = total_cases - len(failures)
    return {
        "model": model,
        "total_cases": total_cases,
        "route_counts": route_counts,
        "expected_pass_rate": (expected_ok / total_cases) if total_cases else 0.0,
        "empty_output_count": empty_outputs,
        "route_variants": route_variants,
        "unstable_cases": unstable_cases,
        "risk_ranges": risk_ranges,
        "failures": failures,
        "stable": total_cases > 0 and not failures and not unstable_cases,
    }


def _summarize_cases(models: list[str], model_summaries: dict[str, dict], contracts: dict[str, dict]) -> dict[str, dict]:
    summaries: dict[str, dict] = {}
    for case_id, contract in contracts.items():
        variants = {
            model: model_summaries.get(model, {}).get("route_variants", {}).get(case_id, [])
            for model in models
            if case_id in model_summaries.get(model, {}).get("route_variants", {})
        }
        failures = [
            {"model": model, **failure}
            for model, summary in model_summaries.items()
            for failure in summary.get("failures", [])
            if failure.get("case_id") == case_id
        ]
        summaries[case_id] = {
            **contract,
            "model_route_variants": variants,
            "failing_models": sorted({item["model"] for item in failures}),
            "failure_count": len(failures),
        }
    return summaries


def summarize_stability(
    *,
    run_id: str,
    suite_id: str,
    policy_profile: str,
    models: list[str],
    rounds: list[dict],
    round_artifacts: list[str] | None = None,
) -> dict:
    contracts = _case_contracts(suite_id)
    model_summaries = {model: _summarize_model(model, rounds, contracts) for model in models}
    stable_models = [model for model, summary in model_summaries.items() if summary["stable"]]
    unstable_models = [model for model in models if model not in stable_models]
    response = ExperimentStabilityResponse(
        run_id=run_id,
        suite_id=suite_id,
        policy_profile=policy_profile,
        rounds=len(rounds),
        models=models,
        round_artifacts=round_artifacts or [],
        model_summaries=model_summaries,
        case_summaries=_summarize_cases(models, model_summaries, contracts),
        stable_models=stable_models,
        unstable_models=unstable_models,
        key_findings=[
            "Stable models must match expected routes, produce non-empty allowed outputs, and keep route decisions identical across rounds.",
            "This view is designed to catch intermittent policy drift that a single model matrix run cannot expose.",
        ],
    )
    return response.model_dump()


def run_stability_experiment(
    *,
    suite_id: str,
    policy_profile: str,
    models: list[str],
    rounds: int = 3,
    base_session_id: str | None = None,
    seed: int = 77,
) -> tuple[dict, list[dict]]:
    run_id = base_session_id or f"{suite_id}-stability-{uuid4().hex[:8]}"
    matrices = [
        run_model_matrix(
            suite_id=suite_id,
            policy_profile=policy_profile,
            models=models,
            base_session_id=f"{run_id}-r{round_index}",
            seed=seed + round_index,
        )
        for round_index in range(1, rounds + 1)
    ]
    return summarize_stability(run_id=run_id, suite_id=suite_id, policy_profile=policy_profile, models=models, rounds=matrices), matrices
