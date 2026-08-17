from __future__ import annotations

import hashlib
import json
import math
import os
import re
from collections import Counter
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import httpx


OLLAMA_BASE_URL = os.environ.get("GUARDX_OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
QDRANT_BASE_URL = os.environ.get("GUARDX_QDRANT_BASE_URL", "http://127.0.0.1:6333").rstrip("/")
BGE_MODEL = os.environ.get("GUARDX_RAG_EMBEDDING_MODEL", "bge-m3").strip() or "bge-m3"
QDRANT_COLLECTION = os.environ.get("GUARDX_QDRANT_COLLECTION", "guardx_demo_bge_m3_v1").strip() or "guardx_demo_bge_m3_v1"


def _tokens(text: str) -> list[str]:
    lowered = str(text or "").lower()
    words = re.findall(r"[a-z0-9_./:-]+", lowered)
    chinese = re.findall(r"[\u4e00-\u9fff]", lowered)
    bigrams = ["".join(chinese[index:index + 2]) for index in range(max(0, len(chinese) - 1))]
    return words + chinese + bigrams


def chunk_documents(documents: list[dict[str, str]], chunk_size: int = 520, overlap: int = 70) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    for document_index, document in enumerate(documents):
        source = str(document.get("source") or f"document-{document_index + 1}")[:240]
        text = str(document.get("text") or "").strip()
        if not text:
            continue
        paragraphs = [part.strip() for part in re.split(r"\n\s*\n", text) if part.strip()]
        for paragraph_index, paragraph in enumerate(paragraphs):
            if len(paragraph) <= chunk_size:
                pieces = [paragraph]
            else:
                step = max(1, chunk_size - overlap)
                pieces = [paragraph[start:start + chunk_size] for start in range(0, len(paragraph), step)]
            for piece_index, piece in enumerate(pieces):
                chunks.append(
                    {
                        "chunk_id": f"doc-{document_index + 1}-p{paragraph_index + 1}-c{piece_index + 1}",
                        "source": source,
                        "text": piece,
                    }
                )
    return chunks


def _installed_ollama_models(client: httpx.Client) -> set[str]:
    response = client.get(f"{OLLAMA_BASE_URL}/api/tags")
    response.raise_for_status()
    return {
        str(item.get("name") or item.get("model") or "")
        for item in (response.json().get("models") or [])
        if isinstance(item, dict)
    }


def probe_vector_rag() -> dict[str, Any]:
    qdrant_connected = False
    embedding_configured = False
    errors: list[str] = []
    try:
        with httpx.Client(timeout=2.5) as client:
            response = client.get(f"{QDRANT_BASE_URL}/collections")
            qdrant_connected = response.status_code == 200
            if not qdrant_connected:
                errors.append(f"Qdrant HTTP {response.status_code}")
    except Exception:
        errors.append("Qdrant unavailable")
    try:
        with httpx.Client(timeout=2.5) as client:
            installed = _installed_ollama_models(client)
            embedding_configured = BGE_MODEL in installed or f"{BGE_MODEL}:latest" in installed
            if not embedding_configured:
                errors.append(f"Ollama model {BGE_MODEL} not installed")
    except Exception:
        errors.append("Ollama unavailable")
    return {
        "configured": qdrant_connected and embedding_configured,
        "vector_store": "qdrant",
        "vector_store_connected": qdrant_connected,
        "embedding_provider": "ollama",
        "embedding_model": BGE_MODEL,
        "embedding_configured": embedding_configured,
        "collection": QDRANT_COLLECTION,
        "errors": errors,
    }


def _embed_texts(client: httpx.Client, texts: list[str]) -> list[list[float]]:
    response = client.post(
        f"{OLLAMA_BASE_URL}/api/embed",
        json={"model": BGE_MODEL, "input": texts, "truncate": True},
        timeout=120.0,
    )
    response.raise_for_status()
    embeddings = response.json().get("embeddings") or []
    if len(embeddings) != len(texts) or not all(isinstance(item, list) and item for item in embeddings):
        raise RuntimeError("Ollama returned malformed BGE-M3 embeddings")
    return [[float(value) for value in vector] for vector in embeddings]


def _ensure_collection(client: httpx.Client, vector_size: int) -> None:
    response = client.get(f"{QDRANT_BASE_URL}/collections/{QDRANT_COLLECTION}")
    if response.status_code == 200:
        existing = (((response.json().get("result") or {}).get("config") or {}).get("params") or {}).get("vectors") or {}
        existing_size = existing.get("size") if isinstance(existing, dict) else None
        if existing_size and int(existing_size) != int(vector_size):
            raise RuntimeError(f"Qdrant collection vector size is {existing_size}, expected {vector_size}")
        return
    if response.status_code != 404:
        response.raise_for_status()
    created = client.put(
        f"{QDRANT_BASE_URL}/collections/{QDRANT_COLLECTION}",
        json={"vectors": {"size": vector_size, "distance": "Cosine"}},
        timeout=30.0,
    )
    created.raise_for_status()


def _workspace_id(query: str, documents: list[dict[str, str]]) -> str:
    payload = json.dumps({"query": query, "documents": documents}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def retrieve_qdrant_bge(query: str, documents: list[dict[str, str]], top_k: int = 4) -> dict[str, Any]:
    chunks = chunk_documents(documents)
    if not chunks:
        raise ValueError("at least one non-empty RAG document is required")
    if not str(query or "").strip():
        raise ValueError("RAG query does not contain searchable text")

    workspace_id = _workspace_id(query, documents)
    with httpx.Client(timeout=30.0) as client:
        vectors = _embed_texts(client, [chunk["text"] for chunk in chunks] + [query])
        document_vectors, query_vector = vectors[:-1], vectors[-1]
        _ensure_collection(client, len(query_vector))
        points = []
        for chunk, vector in zip(chunks, document_vectors):
            point_id = str(uuid5(NAMESPACE_URL, f"guardx:{workspace_id}:{chunk['chunk_id']}"))
            points.append(
                {
                    "id": point_id,
                    "vector": vector,
                    "payload": {"workspace_id": workspace_id, **chunk},
                }
            )
        upsert = client.put(
            f"{QDRANT_BASE_URL}/collections/{QDRANT_COLLECTION}/points",
            params={"wait": "true"},
            json={"points": points},
            timeout=60.0,
        )
        upsert.raise_for_status()
        limit = max(1, min(int(top_k), 8, len(chunks)))
        filter_payload = {"must": [{"key": "workspace_id", "match": {"value": workspace_id}}]}
        searched = client.post(
            f"{QDRANT_BASE_URL}/collections/{QDRANT_COLLECTION}/points/query",
            json={"query": query_vector, "filter": filter_payload, "limit": limit, "with_payload": True},
            timeout=60.0,
        )
        if searched.status_code == 404:
            searched = client.post(
                f"{QDRANT_BASE_URL}/collections/{QDRANT_COLLECTION}/points/search",
                json={"vector": query_vector, "filter": filter_payload, "limit": limit, "with_payload": True},
                timeout=60.0,
            )
        searched.raise_for_status()
        raw_result = searched.json().get("result") or []
        hits = (raw_result.get("points") or []) if isinstance(raw_result, dict) else raw_result

    selected: list[dict[str, Any]] = []
    for hit in hits:
        payload = hit.get("payload") or {}
        selected.append(
            {
                "chunk_id": str(payload.get("chunk_id") or "unknown"),
                "source": str(payload.get("source") or "unknown"),
                "text": str(payload.get("text") or ""),
                "score": round(float(hit.get("score") or 0.0), 6),
            }
        )
    if not selected:
        raise RuntimeError("Qdrant returned no chunks for the indexed workspace")
    return {
        "engine": "qdrant-vector-v1",
        "provider_mode": "real-local-vector-retrieval",
        "vector_store": "qdrant",
        "embedding_model": BGE_MODEL,
        "collection": QDRANT_COLLECTION,
        "document_count": len(documents),
        "chunk_count": len(chunks),
        "top_k": len(selected),
        "chunks": selected,
    }


# Explicit legacy baseline for offline regression tests. The live endpoint never
# silently falls back to this implementation.
def retrieve_bm25(query: str, documents: list[dict[str, str]], top_k: int = 4) -> dict[str, Any]:
    chunks = chunk_documents(documents)
    if not chunks:
        raise ValueError("at least one non-empty RAG document is required")
    query_tokens = _tokens(query)
    if not query_tokens:
        raise ValueError("RAG query does not contain searchable text")
    tokenized = [_tokens(chunk["text"]) for chunk in chunks]
    document_frequency: Counter[str] = Counter()
    for tokens in tokenized:
        document_frequency.update(set(tokens))
    average_length = sum(len(tokens) for tokens in tokenized) / max(1, len(tokenized))
    k1 = 1.5
    b = 0.75
    scored: list[dict[str, Any]] = []
    for chunk, tokens in zip(chunks, tokenized):
        frequencies = Counter(tokens)
        length = max(1, len(tokens))
        score = 0.0
        for token in query_tokens:
            frequency = frequencies.get(token, 0)
            if not frequency:
                continue
            df = document_frequency.get(token, 0)
            inverse_frequency = math.log(1 + (len(chunks) - df + 0.5) / (df + 0.5))
            denominator = frequency + k1 * (1 - b + b * length / max(1.0, average_length))
            score += inverse_frequency * (frequency * (k1 + 1)) / denominator
        scored.append({**chunk, "score": round(score, 6)})
    ranked = sorted(scored, key=lambda item: (-item["score"], item["chunk_id"]))
    selected = ranked[: max(1, min(int(top_k), 8))]
    return {
        "engine": "bm25-local-v1",
        "provider_mode": "real-local-retrieval",
        "document_count": len(documents),
        "chunk_count": len(chunks),
        "top_k": len(selected),
        "chunks": selected,
    }
