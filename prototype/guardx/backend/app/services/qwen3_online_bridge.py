from __future__ import annotations

import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.models import AnalysisResult
from app.services.qwen3_online_process import ExternalJsonlWorker


BACKEND_ROOT = Path(__file__).resolve().parents[2]


def external_qwen3_enabled() -> bool:
    return bool(os.environ.get("GUARDX_QWEN3_EXTERNAL_PYTHON", "").strip())


def _external_python() -> str:
    raw = os.environ.get("GUARDX_QWEN3_EXTERNAL_PYTHON", "").strip()
    if not raw:
        raise RuntimeError("GUARDX_QWEN3_EXTERNAL_PYTHON is not configured")
    return raw


def _timeout_seconds() -> float:
    raw = os.environ.get("GUARDX_QWEN3_EXTERNAL_TIMEOUT_SECONDS", "120").strip()
    try:
        return max(1.0, float(raw))
    except ValueError:
        return 120.0


def _mode() -> str:
    raw = os.environ.get("GUARDX_QWEN3_EXTERNAL_MODE", "persistent").strip().lower().replace("-", "_")
    return "oneshot" if raw in {"one_shot", "oneshot", "single"} else "persistent"


def _worker_env() -> dict[str, str]:
    env = os.environ.copy()
    python_path = env.get("PYTHONPATH", "")
    parts = [str(BACKEND_ROOT)]
    if python_path:
        parts.append(python_path)
    env["PYTHONPATH"] = os.pathsep.join(parts)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


def _payload(text: str, surface: str, segments: list[tuple[str, str]] | None) -> dict[str, Any]:
    return {
        "op": "analyze",
        "text": text,
        "surface": surface,
        "segments": [[kind, value] for kind, value in (segments or [])],
    }


def _result_from_response(response: dict[str, Any], *, mode: str, python_path: str) -> AnalysisResult:
    if not response.get("ok"):
        detail = str(response.get("error") or "external qwen3 worker failed")
        raise RuntimeError(detail)
    result = AnalysisResult(**dict(response.get("result") or {}))
    result.metadata = {
        **result.metadata,
        "external_bridge": {
            "enabled": True,
            "mode": mode,
            "python": python_path,
            "timeout_seconds": _timeout_seconds(),
        },
    }
    return result


def _parse_oneshot_stdout(stdout: str) -> dict[str, Any]:
    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("external qwen3 worker returned empty stdout")
    return json.loads(lines[-1])


def _run_oneshot(payload: dict[str, Any], *, python_path: str) -> AnalysisResult:
    request_id = uuid4().hex
    request = {**payload, "request_id": request_id}
    completed = subprocess.run(
        [python_path, "-m", "app.services.qwen3_online_worker"],
        input=json.dumps(request, ensure_ascii=False),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(BACKEND_ROOT),
        env=_worker_env(),
        timeout=_timeout_seconds(),
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()[-800:]
        raise RuntimeError(f"external qwen3 worker exited with {completed.returncode}: {stderr}")
    response = _parse_oneshot_stdout(completed.stdout)
    return _result_from_response(response, mode="oneshot", python_path=python_path)


_WORKER_LOCK = threading.Lock()
_WORKER: ExternalJsonlWorker | None = None
_WORKER_SIGNATURE: tuple[str, ...] | None = None


def reset_external_qwen3_worker() -> None:
    global _WORKER, _WORKER_SIGNATURE
    with _WORKER_LOCK:
        if _WORKER is not None:
            _WORKER.stop()
        _WORKER = None
        _WORKER_SIGNATURE = None


def _persistent_worker(python_path: str) -> ExternalJsonlWorker:
    global _WORKER, _WORKER_SIGNATURE
    signature = (
        python_path,
        os.environ.get("GUARDX_QWEN3_EXTERNAL_TIMEOUT_SECONDS", ""),
        os.environ.get("GUARDX_QWEN3_EXTERNAL_FAKE_RESULT", ""),
        os.environ.get("GUARDX_QWEN3_ONLINE_DEVICE", ""),
        os.environ.get("GUARDX_QWEN3_ONLINE_POLICY_PATH", ""),
    )
    with _WORKER_LOCK:
        if _WORKER is None or _WORKER_SIGNATURE != signature:
            if _WORKER is not None:
                _WORKER.stop()
            _WORKER = ExternalJsonlWorker(
                [python_path, "-m", "app.services.qwen3_online_worker", "--jsonl"],
                cwd=BACKEND_ROOT,
                env=_worker_env(),
                timeout_seconds=_timeout_seconds(),
            )
            _WORKER_SIGNATURE = signature
        return _WORKER


def analyze_external_qwen3_online(
    text: str,
    *,
    surface: str = "default",
    segments: list[tuple[str, str]] | None = None,
) -> AnalysisResult:
    python_path = _external_python()
    payload = _payload(text, surface, segments)
    if _mode() == "oneshot":
        return _run_oneshot(payload, python_path=python_path)
    request = {**payload, "request_id": uuid4().hex}
    response = _persistent_worker(python_path).request(request)
    return _result_from_response(response, mode="persistent", python_path=python_path)
