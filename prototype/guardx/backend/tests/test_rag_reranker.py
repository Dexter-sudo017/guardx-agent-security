from app.services import rag_reranker


def test_bge_reranker_reorders_vector_candidates(monkeypatch):
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
