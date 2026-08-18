from __future__ import annotations

import atexit
import json
import os
import re
import subprocess
import threading
from pathlib import Path
from typing import Any


CROSS_ENCODER_MODEL = os.environ.get("GUARDX_RAG_CROSS_ENCODER_MODEL", "BAAI/bge-reranker-v2-m3").strip() or "BAAI/bge-reranker-v2-m3"
RERANKER_MODEL = "BAAI/bge-m3-dense-hybrid-rerank-v1"
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
    mode = os.environ.get("GUARDX_RAG_RERANKER_MODE", "dense-hybrid").strip().lower()
    if mode == "cross-encoder":
        result = _worker_request({"query": query, "chunks": chunks, "top_k": top_k})
        return {"model": CROSS_ENCODER_MODEL, "provider": "FlagEmbedding", "chunks": result["chunks"]}
    return {
        "model": RERANKER_MODEL,
        "provider": "Ollama BGE-M3 + GuardX hybrid ranker",
        "chunks": _dense_hybrid_rerank(query, chunks, top_k),
    }


def _rank_tokens(text: str) -> set[str]:
    lowered = str(text or "").lower()
    words = set(re.findall(r"[a-z0-9_./:-]+", lowered))
    chinese = re.findall(r"[\u4e00-\u9fff]", lowered)
    words.update(chinese)
    words.update("".join(chinese[index:index + 2]) for index in range(max(0, len(chinese) - 1)))
    return {token for token in words if token}


def _dense_hybrid_rerank(query: str, chunks: list[dict[str, Any]], top_k: int) -> list[dict[str, Any]]:
    """Second-stage rerank over BGE-M3/Qdrant candidates with query coverage.

    The vector score is produced by the real BGE-M3 embedding route. Query-term
    coverage supplies a lightweight second signal that is stable on 16 GB demo
    machines where the 2.27 GB cross-encoder cannot be loaded safely.
    """
    query_tokens = _rank_tokens(query)
    ranked: list[dict[str, Any]] = []
    for chunk in chunks:
        vector_score = float(chunk.get("score") or 0.0)
        chunk_tokens = _rank_tokens(str(chunk.get("text") or ""))
        coverage = len(query_tokens & chunk_tokens) / max(1, len(query_tokens))
        rerank_score = 0.65 * max(0.0, min(1.0, vector_score)) + 0.35 * coverage
        ranked.append(
            {
                **chunk,
                "vector_score": round(vector_score, 6),
                "query_coverage": round(coverage, 6),
                "rerank_score": round(rerank_score, 6),
                "score": round(rerank_score, 6),
            }
        )
    ranked.sort(key=lambda item: (-item["rerank_score"], str(item.get("chunk_id") or "")))
    return ranked[: max(1, min(int(top_k), 8))]
