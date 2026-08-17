import pytest

from app.services import live_rag
from app.services.live_rag import chunk_documents, retrieve_bm25, retrieve_qdrant_bge


class _FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeVectorClient:
    def __init__(self, *args, **kwargs):
        self.points = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def get(self, url, **_kwargs):
        if url.endswith("/api/tags"):
            return _FakeResponse(200, {"models": [{"name": "bge-m3:latest"}]})
        if url.endswith("/collections"):
            return _FakeResponse(200, {"result": {"collections": []}})
        return _FakeResponse(404, {})

    def put(self, url, json=None, **_kwargs):
        if url.endswith("/points"):
            self.points = (json or {}).get("points", [])
        return _FakeResponse(200, {"status": "ok"})

    def post(self, url, json=None, **_kwargs):
        if url.endswith("/api/embed"):
            texts = (json or {}).get("input", [])
            return _FakeResponse(200, {"embeddings": [[1.0, float(index)] for index, _text in enumerate(texts)]})
        if url.endswith("/points/query"):
            return _FakeResponse(
                200,
                {"result": {"points": [{"score": 0.91, "payload": {"chunk_id": "doc-1-p1-c1", "source": "policy.md", "text": "安全规则"}}]}},
            )
        raise AssertionError(url)


def test_live_rag_chunks_documents_with_provenance():
    chunks = chunk_documents([{"source": "policy.md", "text": "第一段安全要求。\n\n第二段审计要求。"}])
    assert len(chunks) == 2
    assert {item["source"] for item in chunks} == {"policy.md"}
    assert chunks[0]["chunk_id"].startswith("doc-1-")


def test_live_rag_retrieves_relevant_chinese_chunk():
    result = retrieve_bm25(
        "供应链收入增长多少",
        [
            {"source": "finance.md", "text": "供应链报告显示收入增长百分之十八。"},
            {"source": "security.md", "text": "安全策略要求审批所有外部导出。"},
        ],
        top_k=1,
    )
    assert result["provider_mode"] == "real-local-retrieval"
    assert result["chunks"][0]["source"] == "finance.md"


def test_live_rag_requires_documents_and_query_tokens():
    with pytest.raises(ValueError, match="document"):
        retrieve_bm25("查询", [], top_k=2)
    with pytest.raises(ValueError, match="searchable"):
        retrieve_bm25("", [{"source": "a", "text": "content"}], top_k=2)


def test_qdrant_bge_retrieval_reports_real_vector_provenance(monkeypatch):
    monkeypatch.setattr(live_rag.httpx, "Client", _FakeVectorClient)
    result = retrieve_qdrant_bge("安全要求", [{"source": "policy.md", "text": "安全规则"}], top_k=1)
    assert result["engine"] == "qdrant-vector-v1"
    assert result["vector_store"] == "qdrant"
    assert result["embedding_model"] == "bge-m3"
    assert result["provider_mode"] == "real-local-vector-retrieval"
    assert result["chunks"][0]["score"] == 0.91


def test_vector_probe_accepts_ollama_latest_tag(monkeypatch):
    monkeypatch.setattr(live_rag.httpx, "Client", _FakeVectorClient)
    status = live_rag.probe_vector_rag()
    assert status["configured"] is True
    assert status["embedding_configured"] is True
