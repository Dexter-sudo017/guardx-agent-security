from app.services.experiment_suite_registry import experiment_suite_cases


def suite_expectations(suite_id: str) -> dict[str, str]:
    return {case.case_id: case.expectation for case in experiment_suite_cases(suite_id)}


def suite_expected_routes(suite_id: str) -> dict[str, list[str]]:
    return {case.case_id: list(case.expected_routes) for case in experiment_suite_cases(suite_id)}


def percent(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(float(numerator) / float(denominator), 6)


def latency_summary(latencies: list[float]) -> dict[str, float]:
    if not latencies:
        return {"avg_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
    ordered = sorted(latencies)
    p95_index = min(len(ordered) - 1, int(round((len(ordered) - 1) * 0.95)))
    return {"avg_ms": round(sum(ordered) / len(ordered), 3), "p95_ms": round(ordered[p95_index], 3), "max_ms": round(max(ordered), 3)}
