from typing import Any

from app.audit.embedding_ablation_utils import latency_summary, percent, suite_expectations, suite_expected_routes


def summarize_ablation_matrix(matrix: dict[str, Any], *, suite_id: str) -> dict[str, Any]:
    expectations = suite_expectations(suite_id)
    expected_routes = suite_expected_routes(suite_id)
    route_counts: dict[str, int] = {}
    surface_counts: dict[str, int] = {}
    provider_counts: dict[str, int] = {}
    provider_failure_count = qwen3_error_count = direct_embedding_disabled_count = 0
    attack_total = attack_caught = benign_total = benign_allowed = route_mismatch_total = 0
    risk_scores: list[float] = []
    latencies: list[float] = []
    for run in matrix.get("runs", []):
        for case in run.get("cases", []):
            route = str(case.get("route", "unknown"))
            route_counts[route] = route_counts.get(route, 0) + 1
            surface = str(case.get("surface", "unknown"))
            surface_counts[surface] = surface_counts.get(surface, 0) + 1
            for provider_id in case.get("risk_provider_ids", []) or []:
                provider_counts[str(provider_id)] = provider_counts.get(str(provider_id), 0) + 1
            provider_failure_count += int(case.get("risk_provider_failure_count") or 0)
            labels = {str(label) for label in case.get("embedding_labels", []) or []}
            metadata_keys = {str(key) for key in case.get("embedding_metadata_keys", []) or []}
            qwen3_error_count += int("qwen3_joint_online_error" in labels)
            direct_embedding_disabled_count += int("embedding_disabled" in labels or "embedding_disabled" in metadata_keys)
            case_id = str(case.get("case_id", ""))
            expectation = expectations.get(case_id, "mixed")
            if expectation == "attack":
                attack_total += 1
                attack_caught += int(route in {"review", "block"})
            elif expectation == "benign":
                benign_total += 1
                benign_allowed += int(route == "allow")
            expected = expected_routes.get(case_id) or []
            route_mismatch_total += int(bool(expected and route not in expected))
            risk_scores.append(float(case.get("risk_score") or 0.0))
            latencies.append(float(case.get("latency_ms") or 0.0))
    total_cases = sum(route_counts.values())
    return {
        "total_cases": total_cases,
        "route_counts": dict(sorted(route_counts.items())),
        "surface_counts": dict(sorted(surface_counts.items())),
        "provider_counts": dict(sorted(provider_counts.items())),
        "provider_failure_count": provider_failure_count,
        "qwen3_error_count": qwen3_error_count,
        "direct_embedding_disabled_count": direct_embedding_disabled_count,
        "attack_total": attack_total,
        "attack_caught": attack_caught,
        "attack_catch_rate": percent(attack_caught, attack_total),
        "benign_total": benign_total,
        "benign_allowed": benign_allowed,
        "false_positive_rate": percent(benign_total - benign_allowed, benign_total),
        "false_positive_allow_rate": percent(benign_allowed, benign_total),
        "review_rate": percent(route_counts.get("review", 0), total_cases),
        "block_rate": percent(route_counts.get("block", 0), total_cases),
        "allow_rate": percent(route_counts.get("allow", 0), total_cases),
        "route_mismatch_total": route_mismatch_total,
        "avg_risk_score": round(sum(risk_scores) / len(risk_scores), 6) if risk_scores else 0.0,
        "latency": latency_summary(latencies),
    }
