from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import traceback
from typing import Any


def _dump_model(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict"):
        return value.dict()
    return dict(value)


def _json_default(value: Any) -> Any:
    if hasattr(value, "item"):
        return value.item()
    if hasattr(value, "tolist"):
        return value.tolist()
    return str(value)


def _segments_from_payload(raw: Any) -> list[tuple[str, str]] | None:
    if not isinstance(raw, list):
        return None
    segments: list[tuple[str, str]] = []
    for item in raw:
        if isinstance(item, dict):
            kind = item.get("kind") or item.get("role") or item.get("source") or "user"
            value = item.get("text") or item.get("content") or item.get("value") or ""
            if str(value).strip():
                segments.append((str(kind), str(value)))
        elif isinstance(item, (list, tuple)) and len(item) >= 2 and str(item[1]).strip():
            segments.append((str(item[0]), str(item[1])))
    return segments or None


def _fake_result() -> Any | None:
    raw = os.environ.get("GUARDX_QWEN3_EXTERNAL_FAKE_RESULT")
    if not raw:
        return None
    from app.models import AnalysisResult

    return AnalysisResult(**json.loads(raw))


def _run_analysis(payload: dict[str, Any]) -> dict[str, Any]:
    fake = _fake_result()
    if fake is not None:
        result = _dump_model(fake)
        if os.environ.get("GUARDX_QWEN3_EXTERNAL_ECHO_TEXT", "").strip().lower() in {"1", "true", "yes", "on"}:
            metadata = dict(result.get("metadata") or {})
            metadata["worker_echo_text"] = payload.get("text")
            metadata["worker_echo_segments"] = payload.get("segments")
            result["metadata"] = metadata
        return result

    from app.guards import embedding_guard_online

    text = str(payload.get("text") or "")
    surface = str(payload.get("surface") or "default")
    segments = _segments_from_payload(payload.get("segments"))
    with contextlib.redirect_stdout(sys.stderr):
        result = embedding_guard_online.analyze(text, surface=surface, segments=segments)
    return _dump_model(result)


def _handle(payload: dict[str, Any]) -> dict[str, Any]:
    operation = str(payload.get("op") or "analyze")
    if operation == "health":
        return {"status": "ok", "fake": bool(os.environ.get("GUARDX_QWEN3_EXTERNAL_FAKE_RESULT"))}
    if operation != "analyze":
        raise ValueError(f"Unsupported qwen3 worker operation: {operation}")
    return _run_analysis(payload)


def _response_for(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = payload.get("request_id")
    try:
        return {"request_id": request_id, "ok": True, "result": _handle(payload)}
    except Exception as exc:
        return {
            "request_id": request_id,
            "ok": False,
            "error": str(exc),
            "traceback": traceback.format_exc(limit=8),
        }


def _emit(response: dict[str, Any]) -> None:
    print(json.dumps(response, ensure_ascii=False, default=_json_default), flush=True)


def _run_jsonl() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except Exception as exc:
            _emit({"request_id": None, "ok": False, "error": f"invalid json: {exc}"})
            continue
        _emit(_response_for(payload))


def _run_oneshot() -> None:
    payload = json.load(sys.stdin)
    _emit(_response_for(payload))


def main() -> None:
    parser = argparse.ArgumentParser(description="External Qwen3 online embedding worker for GuardX.")
    parser.add_argument("--jsonl", action="store_true", help="Keep the worker alive and serve newline-delimited JSON requests.")
    args = parser.parse_args()
    if args.jsonl:
        _run_jsonl()
    else:
        _run_oneshot()


if __name__ == "__main__":
    main()
