import base64

import pytest

from app.services import document_ingestion
from app.services.document_ingestion import parse_document_bytes, parse_file_payloads


class _Payload:
    def __init__(self, filename: str, data: bytes):
        self.filename = filename
        self.content_base64 = base64.b64encode(data).decode("ascii")


def test_txt_ingestion_is_real_utf8_and_auditable():
    parsed = parse_document_bytes(filename="review.txt", content="采购审计结论：通过。".encode("utf-8"))
    assert parsed["text"] == "采购审计结论:通过。"
    assert parsed["manifest"]["parser"] == "native-utf8"
    assert len(parsed["manifest"]["sha256"]) == 64


def test_docling_ingestion_uses_converter_and_normalizes_markdown(monkeypatch, tmp_path):
    class _Document:
        pages = {1: object(), 2: object()}

        def export_to_markdown(self):
            return "SUMMARY\\_NORMALIZATION=ENABLED\n\n供应商复核"

    class _Converter:
        def convert(self, _path):
            return type("Result", (), {"document": _Document()})()

    monkeypatch.setattr(document_ingestion, "_docling_converter", lambda: _Converter())
    monkeypatch.setenv("GUARDX_RUNTIME_TEMP", str(tmp_path))
    parsed = parse_document_bytes(filename="policy.pdf", content=b"real-binary-placeholder")
    assert "SUMMARY_NORMALIZATION=ENABLED" in parsed["text"]
    assert parsed["manifest"]["parser"] == "docling"
    assert parsed["manifest"]["page_count"] == 2


def test_document_parser_worker_resolves_app_package_from_arbitrary_cwd(tmp_path):
    """The isolated worker must boot even when its caller is outside the backend tree."""
    import os
    import subprocess
    import sys

    worker = document_ingestion._PARSER_WORKER
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, "-u", str(worker)],
        input='{"files": []}',
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=tmp_path,
        env=env,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert '"documents": []' in completed.stdout


def test_isolated_ingestion_routes_text_layer_pdf_without_docling_worker(monkeypatch):
    expected = {
        "source": "policy.pdf",
        "text": "policy text",
        "manifest": {"filename": "policy.pdf", "parser": "pypdf-text-layer"},
    }
    monkeypatch.setattr(document_ingestion, "_parse_pdf_text_layer", lambda **_kwargs: expected)
    monkeypatch.setattr(document_ingestion, "_run_parser_worker", lambda _items: pytest.fail("PDF must not load Docling worker"))

    assert document_ingestion.parse_documents_isolated([{"filename": "policy.pdf", "content": b"pdf"}]) == [expected]


def test_file_payload_validation_rejects_unknown_and_bad_base64():
    with pytest.raises(ValueError, match="supported"):
        parse_document_bytes(filename="archive.zip", content=b"x")
    with pytest.raises(ValueError, match="base64"):
        parse_file_payloads([type("Bad", (), {"filename": "a.txt", "content_base64": "%%%"})()])


def test_multiple_file_payloads_preserve_provenance():
    documents, manifest = parse_file_payloads(
        [_Payload("a.txt", b"alpha"), _Payload("b.txt", b"beta")]
    )
    assert [item["source"] for item in documents] == ["a.txt", "b.txt"]
    assert [item["filename"] for item in manifest] == ["a.txt", "b.txt"]
