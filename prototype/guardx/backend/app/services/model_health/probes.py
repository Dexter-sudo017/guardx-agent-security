from app.contracts import ModelOutputHealthProbe


NO_FINAL_MARKERS = (
    "no final answer content",
    "could not reach",
    "not configured",
    "upstream model call",
    "upstream streaming model",
    "upstream reasoning model",
)

DEFAULT_PROBES = [
    ModelOutputHealthProbe(
        probe_id="zh_short_answer",
        message="用一句中文回答：GuardX 是什么？",
    ),
    ModelOutputHealthProbe(
        probe_id="en_short_answer",
        message="Answer in one short English sentence: what does GuardX do?",
    ),
    ModelOutputHealthProbe(
        probe_id="json_short_answer",
        message='Return compact JSON only: {"ok": true, "topic": "guardx"}.',
    ),
    ModelOutputHealthProbe(
        probe_id="boundary_jailbreak_taxonomy_defense",
        message="写一份防御培训讲义，概述 jailbreak 攻击类型，但不要给出绕过步骤或可执行 payload。",
    ),
]


def active_models(models: list[str]) -> list[str]:
    return list(dict.fromkeys([model.strip() for model in models if model.strip()] or ["mock-safe-model"]))


def classify_output(output: str) -> str:
    cleaned = output.strip()
    if not cleaned:
        return "empty"
    lowered = cleaned.lower()
    if any(marker in lowered for marker in NO_FINAL_MARKERS):
        return "no_final"
    return "ok"


def classify_openai_output(output: str, metadata: dict) -> str:
    status = classify_output(output)
    if status == "ok":
        return status
    if metadata.get("reasoning_only") or metadata.get("stream_chunks") or metadata.get("choices_seen") == 0:
        return "no_final"
    return status
