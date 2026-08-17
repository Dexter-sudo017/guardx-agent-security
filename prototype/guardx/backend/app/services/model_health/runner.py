from uuid import uuid4

from app.adapters.registry import AdapterRegistry
from app.contracts import ModelOutputHealthProbe, ModelOutputHealthResponse, ModelOutputHealthResult
from app.services.model_health.probes import DEFAULT_PROBES, active_models
from app.services.model_health.transport import probe_model


def summarize_results(results: list[ModelOutputHealthResult]) -> dict:
    by_model: dict[str, dict] = {}
    totals = {"ok": 0, "empty": 0, "no_final": 0, "unavailable": 0, "error": 0}
    for result in results:
        totals[result.status] += 1
        bucket = by_model.setdefault(
            result.model,
            {
                "probe_count": 0,
                "ok": 0,
                "empty": 0,
                "no_final": 0,
                "unavailable": 0,
                "error": 0,
                "latency_ms_avg": 0.0,
                "content_length_avg": 0.0,
                "usable_for_matrix": False,
            },
        )
        bucket["probe_count"] += 1
        bucket[result.status] += 1
        bucket["latency_ms_avg"] += result.latency_ms
        bucket["content_length_avg"] += result.content_length
    for bucket in by_model.values():
        probe_count = max(1, int(bucket["probe_count"]))
        bucket["latency_ms_avg"] = round(float(bucket["latency_ms_avg"]) / probe_count, 3)
        bucket["content_length_avg"] = round(float(bucket["content_length_avg"]) / probe_count, 3)
        bucket["health_rate"] = round(float(bucket["ok"]) / probe_count, 4)
        bucket["usable_for_matrix"] = bucket["ok"] == bucket["probe_count"]
    return {"total_probes": len(results), "status_counts": totals, "models": by_model}


def run_model_output_health(
    *,
    models: list[str],
    run_id: str | None = None,
    probes: list[ModelOutputHealthProbe] | None = None,
    timeout_s: float = 45.0,
) -> dict:
    registry = AdapterRegistry()
    selected_models = active_models(models)
    selected_probes = probes or DEFAULT_PROBES
    results = [
        probe_model(registry, model, probe, timeout_s)
        for model in selected_models
        for probe in selected_probes
    ]
    response = ModelOutputHealthResponse(
        run_id=run_id or f"model-output-health-{uuid4().hex[:8]}",
        models=selected_models,
        probes=selected_probes,
        results=results,
        summary=summarize_results(results),
    )
    return response.model_dump()
