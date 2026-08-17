from typing import Any


def mode_case_comparison(mode_results: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for mode, matrix in mode_results.items():
        for run in matrix.get("runs", []):
            model = str(run.get("model", "unknown"))
            for case in run.get("cases", []):
                key = (model, str(case.get("case_id", "unknown")))
                row = rows.setdefault(key, {"model": model, "case_id": key[1], "surface": case.get("surface"), "modes": {}})
                row["modes"][mode] = {
                    "route": case.get("route"),
                    "action": case.get("action"),
                    "risk_score": case.get("risk_score"),
                    "latency_ms": case.get("latency_ms"),
                    "provider_failure_count": case.get("risk_provider_failure_count", 0),
                }
    for row in rows.values():
        cells = list(row["modes"].values())
        row["diff"] = {
            "route_variants": sorted({str(cell.get("route")) for cell in cells}),
            "risk_min": min(float(cell.get("risk_score") or 0.0) for cell in cells) if cells else 0.0,
            "risk_max": max(float(cell.get("risk_score") or 0.0) for cell in cells) if cells else 0.0,
        }
        row["diff"]["risk_range"] = round(row["diff"]["risk_max"] - row["diff"]["risk_min"], 6)
    return [rows[key] for key in sorted(rows)]


def deltas_vs_baseline(summaries: dict[str, dict[str, Any]], baseline_mode: str = "none") -> dict[str, dict[str, Any]]:
    baseline = summaries.get(baseline_mode, {})
    return {mode: _delta_summary(summary, baseline, baseline_mode) for mode, summary in summaries.items() if mode != baseline_mode}


def _numeric_delta(value: Any, baseline: Any) -> float | None:
    if value is None or baseline is None:
        return None
    try:
        return round(float(value) - float(baseline), 6)
    except (TypeError, ValueError):
        return None


def _delta_summary(summary: dict[str, Any], baseline: dict[str, Any], baseline_mode: str) -> dict[str, Any]:
    return {
        "baseline_mode": baseline_mode,
        "attack_catch_rate_delta": _numeric_delta(summary.get("attack_catch_rate"), baseline.get("attack_catch_rate")),
        "false_positive_rate_delta": _numeric_delta(summary.get("false_positive_rate"), baseline.get("false_positive_rate")),
        "review_rate_delta": _numeric_delta(summary.get("review_rate"), baseline.get("review_rate")),
        "allow_rate_delta": _numeric_delta(summary.get("allow_rate"), baseline.get("allow_rate")),
        "block_rate_delta": _numeric_delta(summary.get("block_rate"), baseline.get("block_rate")),
        "avg_risk_score_delta": _numeric_delta(summary.get("avg_risk_score"), baseline.get("avg_risk_score")),
        "avg_latency_ms_delta": _numeric_delta(dict(summary.get("latency", {})).get("avg_ms"), dict(baseline.get("latency", {})).get("avg_ms")),
        "provider_failure_count_delta": int(summary.get("provider_failure_count") or 0) - int(baseline.get("provider_failure_count") or 0),
        "qwen3_error_count_delta": int(summary.get("qwen3_error_count") or 0) - int(baseline.get("qwen3_error_count") or 0),
        "route_mismatch_total_delta": int(summary.get("route_mismatch_total") or 0) - int(baseline.get("route_mismatch_total") or 0),
    }
