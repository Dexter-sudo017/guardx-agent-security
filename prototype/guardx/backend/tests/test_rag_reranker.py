from app.services import rag_reranker


def test_bge_reranker_reorders_vector_candidates(monkeypatch):
    monkeypatch.setenv("GUARDX_RAG_RERANKER_MODE", "cross-encoder")
    def _worker_request(payload):
        assert payload["query"] == "采购风险"
        return {
            "chunks": [
                {**payload["chunks"][1], "vector_score": 0.71, "rerank_score": 0.93, "score": 0.93}
            ]
        }

    monkeypatch.setattr(rag_reranker, "_worker_request", _worker_request)
    result = rag_reranker.rerank_bge(
        "采购风险",
        [
            {"chunk_id": "a", "text": "无关文本", "score": 0.98},
            {"chunk_id": "b", "text": "采购付款风险", "score": 0.71},
        ],
        top_k=1,
    )
    assert result["chunks"][0]["chunk_id"] == "b"
    assert result["chunks"][0]["vector_score"] == 0.71
    assert result["chunks"][0]["rerank_score"] == 0.93


def test_bge_m3_dense_hybrid_reranker_is_low_memory_and_reorders(monkeypatch):
    monkeypatch.setenv("GUARDX_RAG_RERANKER_MODE", "dense-hybrid")
    result = rag_reranker.rerank_bge(
        "采购风险",
        [
            {"chunk_id": "a", "text": "无关文本", "score": 0.98},
            {"chunk_id": "b", "text": "采购付款风险", "score": 0.71},
        ],
        top_k=1,
    )
    assert result["provider"] == "Ollama BGE-M3 + GuardX hybrid ranker"
    assert result["model"] == "BAAI/bge-m3-dense-hybrid-rerank-v1"
    assert result["chunks"][0]["chunk_id"] == "b"
    assert result["chunks"][0]["query_coverage"] > 0
