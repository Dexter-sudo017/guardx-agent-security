from __future__ import annotations

import atexit
import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Any


RERANKER_MODEL = os.environ.get("GUARDX_RAG_RERANKER_MODEL", "BAAI/bge-reranker-v2-m3").strip() or "BAAI/bge-reranker-v2-m3"
_DEFAULT_PYTHON = Path(r"E:\GuardX\runtime\bge-reranker-venv\Scripts\python.exe")
_WORKER_SCRIPT = Path(__file__).with_name("rag_reranker_worker.py")
_LOCK = threading.Lock()
_WORKER: subprocess.Popen[str] | None = None


def _stop_worker() -> None:
    global _WORKER
    if _WORKER and _WORKER.poll() is None:
        _WORKER.terminate()
        try:
            _WORKER.wait(timeout=15)
        except subprocess.TimeoutExpired:
            _WORKER.kill()
            _WORKER.wait(timeout=5)
    _WORKER = None


atexit.register(_stop_worker)


def release_reranker() -> None:
    """Release the reranker before Ollama loads the embedding model."""
    with _LOCK:
        _stop_worker()


def _start_worker() -> subprocess.Popen[str]:
    global _WORKER
    if _WORKER and _WORKER.poll() is None:
        return _WORKER
    configured = os.environ.get("GUARDX_RERANKER_PYTHON", "").strip()
    executable = Path(configured) if configured else _DEFAULT_PYTHON
    if not executable.is_file():
        raise RuntimeError(f"isolated BGE reranker runtime not found: {executable}")
    environment = os.environ.copy()
    environment.setdefault("PYTHONUTF8", "1")
    _WORKER = subprocess.Popen(
        [str(executable), "-u", str(_WORKER_SCRIPT)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=environment,
    )
    return _WORKER


def _worker_request(payload: dict[str, Any]) -> dict[str, Any]:
    with _LOCK:
        for attempt in range(2):
            worker = _start_worker()
            assert worker.stdin is not None and worker.stdout is not None
            try:
                worker.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
                worker.stdin.flush()
                response = worker.stdout.readline()
            except (BrokenPipeError, OSError):
                response = ""
            if response:
                result = json.loads(response)
                if result.get("error"):
                    raise RuntimeError(f"BGE reranker worker failed: {result['error']}")
                return result
            detail = ""
            if worker.stderr is not None and worker.poll() is not None:
                detail = worker.stderr.read().strip().splitlines()[-1] if worker.stderr.readable() else ""
            _stop_worker()
            if attempt:
                raise RuntimeError(f"BGE reranker worker stopped without a response: {detail or 'no worker error'}")
    raise RuntimeError("BGE reranker worker stopped without a response")


def rerank_bge(query: str, chunks: list[dict[str, Any]], top_k: int) -> dict[str, Any]:
    if not chunks:
        return {"model": RERANKER_MODEL, "provider": "FlagEmbedding", "chunks": []}
    result = _worker_request({"query": query, "chunks": chunks, "top_k": top_k})
    return {"model": RERANKER_MODEL, "provider": "FlagEmbedding", "chunks": result["chunks"]}
