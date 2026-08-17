from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
from pathlib import Path
from typing import Any


BACKEND_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = Path(__file__).resolve().parents[5]
SRTP_ROOT = PROJECT_ROOT.parent / "srtp" / "eaas-privacy-master"
DEFAULT_CACHE_DIR = PROJECT_ROOT.parent / "models" / "hf"
LATEST_DECODER_SUMMARY = BACKEND_ROOT / "data" / "experiment_runs" / "latest_decoder_probe_summary.json"
DEFAULT_VARIANT = "noisy_cls"
SUPPORTED_DEMO_VARIANTS = {"noisy_cls", "gaussian_cls"}
RUNTIME_CANDIDATES = [
    os.environ.get("GUARDX_SRTP_PYTHON", ""),
    "D:/anaconda_dress/envs/yolo/python.exe",
    str(PROJECT_ROOT.parent / ".venv_vec2text_torch26" / "Scripts" / "python.exe"),
]
_WORKER_LOCK = threading.Lock()
_WORKER: subprocess.Popen[str] | None = None
_WORKER_RUNTIME: Path | None = None


def _runtime_python() -> Path | None:
    return next((Path(raw) for raw in RUNTIME_CANDIDATES if raw and Path(raw).is_file()), None)


def _latest_checkpoint(variant: str) -> Path | None:
    if variant not in SUPPORTED_DEMO_VARIANTS:
        return None
    if LATEST_DECODER_SUMMARY.exists():
        try:
            summary = json.loads(LATEST_DECODER_SUMMARY.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            summary = {}
        checkpoint = Path(str(summary.get("best_decoder_checkpoint") or ""))
        if summary.get("best_embedding_variant") == variant and checkpoint.is_file():
            return checkpoint
    root = SRTP_ROOT / "evaluation" / "decoder_probe"
    if not root.exists():
        return None
    candidates = list(root.glob(f"*/decoders/projection_prefix_{variant}.pt"))
    return max(candidates, key=lambda item: item.stat().st_mtime) if candidates else None


def run_decoder_demo(source_text: str, *, variant: str = DEFAULT_VARIANT, show_reconstruction: bool = True) -> dict[str, Any]:
    text = source_text.strip()
    if not text:
        return _unavailable("empty_source_text")
    if variant not in SUPPORTED_DEMO_VARIANTS:
        return _unavailable(f"unsupported_variant:{variant}")
    runtime = _runtime_python()
    checkpoint = _latest_checkpoint(variant)
    if runtime is None:
        return _unavailable("srtp_python_runtime_not_found")
    if checkpoint is None:
        return _unavailable(f"decoder_checkpoint_not_found:{variant}")
    payload = {"source_text": text[:2000], "variant": variant, "checkpoint_path": str(checkpoint), "model_name": "distilbert-base-uncased", "cache_dir": str(DEFAULT_CACHE_DIR), "device": os.environ.get("GUARDX_SRTP_DEVICE", "cpu"), "max_length": 96, "noise_mechanism": "gaussian", "noise_std": float(os.environ.get("GUARDX_SRTP_NOISE_STD", "0.25")), "min_trusted_token_f1": float(os.environ.get("GUARDX_SRTP_MIN_TRUSTED_TOKEN_F1", "0.25")), "show_reconstruction": show_reconstruction}
    return _run_via_worker(runtime, payload)


def _run_once(runtime: Path, payload: dict[str, Any]) -> dict[str, Any]:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "TRANSFORMERS_VERBOSITY": "error"}
    completed = subprocess.run(
        [str(runtime), "-m", "attack.text_privacy_demo", "--json"],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        cwd=SRTP_ROOT,
        encoding="utf-8",
        env=env,
        timeout=int(os.environ.get("GUARDX_SRTP_DEMO_TIMEOUT_SECONDS", "180")),
        check=False,
    )
    return _decode_subprocess_result(completed)


def _run_via_worker(runtime: Path, payload: dict[str, Any]) -> dict[str, Any]:
    if os.environ.get("GUARDX_SRTP_DEMO_WORKER", "1") == "0":
        return _run_once(runtime, payload)
    with _WORKER_LOCK:
        worker = _ensure_worker(runtime)
        try:
            assert worker.stdin is not None and worker.stdout is not None
            worker.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
            worker.stdin.flush()
            for _attempt in range(20):
                raw = _read_worker_line(worker)
                if not raw:
                    _stop_worker()
                    return _run_once(runtime, payload)
                if raw.lstrip().startswith("{"):
                    return json.loads(raw)
            _stop_worker()
            return _run_once(runtime, payload)
        except (BrokenPipeError, OSError, json.JSONDecodeError):
            _stop_worker()
            return _run_once(runtime, payload)


def _ensure_worker(runtime: Path) -> subprocess.Popen[str]:
    global _WORKER, _WORKER_RUNTIME
    if _WORKER is not None and _WORKER.poll() is None and _WORKER_RUNTIME == runtime:
        return _WORKER
    _stop_worker()
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "TRANSFORMERS_VERBOSITY": "error"}
    _WORKER = subprocess.Popen([str(runtime), "-m", "attack.text_privacy_demo_worker"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=SRTP_ROOT, encoding="utf-8", env=env)
    _WORKER_RUNTIME = runtime
    return _WORKER


def _read_worker_line(worker: subprocess.Popen[str]) -> str:
    assert worker.stdout is not None
    lines: queue.Queue[str] = queue.Queue(maxsize=1)

    def read_line() -> None:
        lines.put(worker.stdout.readline())

    reader = threading.Thread(target=read_line, daemon=True)
    reader.start()
    try:
        return lines.get(timeout=int(os.environ.get("GUARDX_SRTP_DEMO_TIMEOUT_SECONDS", "180")))
    except queue.Empty:
        _stop_worker()
        return ""


def _stop_worker() -> None:
    global _WORKER, _WORKER_RUNTIME
    if _WORKER is not None and _WORKER.poll() is None:
        _WORKER.kill()
    _WORKER = None
    _WORKER_RUNTIME = None


def _decode_subprocess_result(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    try:
        raw_json = next(line for line in completed.stdout.splitlines() if line.strip().startswith("{"))
        result = json.loads(raw_json)
    except (StopIteration, json.JSONDecodeError):
        result = _unavailable("decoder_demo_invalid_json")
    if completed.returncode != 0:
        result.setdefault("available", False)
        result.setdefault("error", completed.stderr.strip() or "decoder_demo_failed")
    return result


def _unavailable(reason: str) -> dict[str, Any]:
    return {"schema_version": "guardx-text-privacy-decoder-demo-v1", "available": False, "eval_only": True, "production_routing": False, "missing_reason": reason}
