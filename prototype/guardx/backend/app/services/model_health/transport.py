import json
from time import perf_counter

import httpx

from app.adapters.openai_compatible import resolve_env
from app.adapters.registry import AdapterRegistry
from app.contracts import ModelOutputHealthProbe, ModelOutputHealthResult
from app.services.model_health.probes import classify_openai_output, classify_output


def unavailable_result(model: str, probe: ModelOutputHealthProbe) -> ModelOutputHealthResult:
    return ModelOutputHealthResult(
        model=model,
        probe_id=probe.probe_id,
        configured=False,
        status="unavailable",
        error_type="ModelNotConfigured",
        error="Model adapter is not configured or not present in models.yaml.",
    )


def content_from_value(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict):
                text = item.get("text") or item.get("content")
                if text:
                    parts.append(str(text))
            elif item:
                parts.append(str(item))
        return "".join(parts)
    return "" if value is None else str(value)


def parse_sse_response(text: str) -> tuple[str, dict]:
    parts: list[str] = []
    metadata = {"stream_chunks": 0, "choices_seen": 0, "finish_reasons": []}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line.removeprefix("data:").strip()
        if payload == "[DONE]":
            continue
        try:
            chunk = json.loads(payload)
        except ValueError:
            metadata["stream_chunks"] += 1
            continue
        metadata["stream_chunks"] += 1
        choices = chunk.get("choices", [])
        metadata["choices_seen"] += len(choices)
        if chunk.get("usage"):
            metadata["usage"] = chunk.get("usage")
        for choice in choices:
            delta = choice.get("delta") or choice.get("message") or {}
            content = content_from_value(delta.get("content"))
            if content:
                parts.append(content)
            finish_reason = choice.get("finish_reason")
            if finish_reason:
                metadata["finish_reasons"].append(finish_reason)
    return "".join(parts), metadata


def parse_json_response(data: dict) -> tuple[str, dict]:
    metadata = {"choices_seen": 0, "finish_reasons": []}
    choices = data.get("choices", [])
    metadata["choices_seen"] = len(choices)
    if data.get("usage"):
        metadata["usage"] = data.get("usage")
    if not choices:
        return "", metadata
    message = choices[0].get("message", {})
    metadata["finish_reasons"] = [item.get("finish_reason") for item in choices if item.get("finish_reason")]
    if message.get("reasoning_content") and not message.get("content"):
        metadata["reasoning_only"] = True
    return content_from_value(message.get("content")), metadata


def openai_health_probe(registry: AdapterRegistry, model: str, probe: ModelOutputHealthProbe, timeout_s: float) -> ModelOutputHealthResult:
    info = registry.get_info(model)
    spec = registry.get_spec(model)
    base_url = resolve_env(spec.get("base_url_env")) or spec.get("base_url")
    api_key = resolve_env(spec.get("api_key_env")) or spec.get("api_key")
    if not info.configured or not base_url or not api_key:
        return unavailable_result(model, probe)
    upstream_model = spec.get("upstream_model") or model
    max_tokens = int(spec.get("health_max_tokens", spec.get("max_tokens", 256)))
    payload = {
        "model": upstream_model,
        "messages": [{"role": "user", "content": probe.message}],
        "temperature": float(spec.get("temperature", 0.2)),
        "max_tokens": max_tokens,
    }
    metadata = {"adapter_type": "openai_compatible", "upstream_model": upstream_model, "base_url_host": str(base_url).split("//")[-1].split("/")[0], "max_tokens": max_tokens}
    started = perf_counter()
    try:
        with httpx.Client(timeout=timeout_s) as client:
            response = client.post(f"{str(base_url).rstrip('/')}/chat/completions", json=payload, headers={"Authorization": f"Bearer {api_key}"})
    except Exception as exc:
        return ModelOutputHealthResult(model=model, probe_id=probe.probe_id, configured=True, status="error", latency_ms=round((perf_counter() - started) * 1000.0, 3), error_type=type(exc).__name__, error=str(exc)[:300], metadata=metadata)
    latency_ms = round((perf_counter() - started) * 1000.0, 3)
    content_type = response.headers.get("content-type", "")
    metadata.update({"status_code": response.status_code, "content_type": content_type})
    if response.status_code >= 400:
        return ModelOutputHealthResult(model=model, probe_id=probe.probe_id, configured=True, status="error", latency_ms=latency_ms, error_type=f"HTTP{response.status_code}", error=response.text[:300], metadata=metadata)
    try:
        output, parsed_metadata = parse_sse_response(response.text) if "text/event-stream" in content_type else parse_json_response(response.json())
    except Exception as exc:
        return ModelOutputHealthResult(model=model, probe_id=probe.probe_id, configured=True, status="error", latency_ms=latency_ms, error_type=type(exc).__name__, error=str(exc)[:300], metadata=metadata)
    metadata.update(parsed_metadata)
    return ModelOutputHealthResult(model=model, probe_id=probe.probe_id, configured=True, status=classify_openai_output(output, metadata), latency_ms=latency_ms, content_length=len(output), output_preview=output[:240], metadata=metadata)


def adapter_health_probe(registry: AdapterRegistry, model: str, probe: ModelOutputHealthProbe) -> ModelOutputHealthResult:
    info = registry.get_info(model)
    spec = registry.get_spec(model)
    if not info.configured:
        return unavailable_result(model, probe)
    adapter = registry.get(model)
    started = perf_counter()
    metadata = {"adapter_type": spec.get("type", info.adapter_type)}
    try:
        output = adapter.generate(probe.message, [], model)
    except Exception as exc:
        return ModelOutputHealthResult(model=model, probe_id=probe.probe_id, configured=True, status="error", latency_ms=round((perf_counter() - started) * 1000.0, 3), error_type=type(exc).__name__, error=str(exc)[:300], metadata=metadata)
    latency_ms = round((perf_counter() - started) * 1000.0, 3)
    return ModelOutputHealthResult(model=model, probe_id=probe.probe_id, configured=True, status=classify_output(output), latency_ms=latency_ms, content_length=len(output), output_preview=output[:240], metadata=metadata)


def probe_model(registry: AdapterRegistry, model: str, probe: ModelOutputHealthProbe, timeout_s: float) -> ModelOutputHealthResult:
    info = registry.get_info(model)
    if info.adapter_type == "openai_compatible":
        return openai_health_probe(registry, model, probe, timeout_s)
    return adapter_health_probe(registry, model, probe)
