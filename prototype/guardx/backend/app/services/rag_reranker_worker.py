from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Any


MODEL_ID = os.environ.get("GUARDX_RAG_RERANKER_MODEL", "BAAI/bge-reranker-v2-m3").strip() or "BAAI/bge-reranker-v2-m3"
LOCAL_MODEL = Path(os.environ.get("GUARDX_RAG_RERANKER_PATH", r"E:\GuardX\models\bge-reranker-v2-m3"))


def _load_model():
    import torch
    from FlagEmbedding import FlagReranker

    location = str(LOCAL_MODEL) if (LOCAL_MODEL / "config.json").is_file() else MODEL_ID
    with contextlib.redirect_stdout(sys.stderr):
        return FlagReranker(location, use_fp16=bool(torch.cuda.is_available()))


def _rerank(model: Any, request: dict[str, Any]) -> list[dict[str, Any]]:
    chunks = list(request.get("chunks") or [])
    pairs = [[str(request.get("query") or ""), str(item.get("text") or "")] for item in chunks]
    with contextlib.redirect_stdout(sys.stderr):
        raw_scores = model.compute_score(pairs, normalize=True)
    scores = raw_scores if isinstance(raw_scores, list) else [raw_scores]
    ranked = []
    for chunk, score in zip(chunks, scores):
        ranked.append(
            {
                **chunk,
                "vector_score": round(float(chunk.get("score") or 0.0), 6),
                "rerank_score": round(float(score), 6),
                "score": round(float(score), 6),
            }
        )
    ranked.sort(key=lambda item: (-item["rerank_score"], str(item.get("chunk_id") or "")))
    top_k = max(1, min(int(request.get("top_k") or 4), 8))
    return ranked[:top_k]


def main() -> int:
    model = _load_model()
    for line in sys.stdin:
        try:
            request = json.loads(line)
            response = {"chunks": _rerank(model, request)}
        except Exception as exc:
            response = {"error": f"{type(exc).__name__}: {exc}"}
        sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
