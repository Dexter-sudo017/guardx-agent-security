from __future__ import annotations

import base64
import gc
import hashlib
import os
import json
import subprocess
import tempfile
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Any


SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".txt"}
MAX_FILE_BYTES = 12 * 1024 * 1024
_PARSER_WORKER = Path(__file__).with_name("document_parser_worker.py")
_DEFAULT_PARSER_PYTHON = Path(r"E:\GuardX\runtime\guardx-venv\Scripts\python.exe")


def _normalize_text(text: str) -> str:
    return unicodedata.normalize("NFKC", str(text or "")).replace("\\_", "_").strip()


@lru_cache(maxsize=1)
def _docling_converter():
    try:
        from docling.datamodel.base_models import InputFormat
        from docling.datamodel.pipeline_options import PdfPipelineOptions
        from docling.document_converter import DocumentConverter, PdfFormatOption
    except ImportError as exc:
        raise RuntimeError("Docling is not installed; install requirements-enterprise-demo.txt") from exc

    # Business PDFs with a usable text layer should not pay the OCR/model cost.
    # Scanned-image OCR remains a separate VLM/OCR path in the reviewer console.
    pdf_options = PdfPipelineOptions(do_ocr=False, do_table_structure=False)
    # torch.compile currently fails on some Windows GBK installations. Disabling
    # compilation preserves the real Docling pipeline and produces stable output.
    pdf_options.layout_options.engine_options.compile_model = False
    return DocumentConverter(
        format_options={
            InputFormat.PDF: PdfFormatOption(pipeline_options=pdf_options),
        }
    )


def release_document_parser() -> None:
    """Release heavyweight Docling models before embedding/reranking starts."""
    _docling_converter.cache_clear()
    gc.collect()
    try:
        import torch

        if torch.cuda.is_available():
            torch.cuda.empty_cache()
    except ImportError:
        pass


def _run_parser_worker(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    configured = os.environ.get("GUARDX_PARSER_PYTHON", "").strip()
    executable = Path(configured) if configured else _DEFAULT_PARSER_PYTHON
    if not executable.is_file():
        raise RuntimeError(f"isolated Docling parser runtime not found: {executable}")
    payload = {
        "files": [
            {"filename": str(item["filename"]), "content_base64": base64.b64encode(item["content"]).decode("ascii")}
            for item in items
        ]
    }
    completed = subprocess.run(
        [str(executable), "-u", str(_PARSER_WORKER)],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=600,
        env={**os.environ, "PYTHONUTF8": "1"},
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()[-1] if completed.stderr.strip() else f"exit {completed.returncode}"
        raise RuntimeError(f"Docling parser worker failed: {detail}")
    response = json.loads(completed.stdout)
    if response.get("error"):
        raise RuntimeError(f"Docling parser worker failed: {response['error']}")
    return list(response["documents"])


def parse_documents_isolated(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not items:
        return []
    results: list[dict[str, Any] | None] = [None] * len(items)
    groups: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, item in enumerate(items):
        extension = Path(str(item["filename"])).suffix.lower()
        if extension == ".txt":
            results[index] = parse_document_bytes(filename=item["filename"], content=item["content"])
        else:
            groups.setdefault(extension, []).append((index, item))
    for group in groups.values():
        parsed_group = _run_parser_worker([item for _, item in group])
        for (index, _), parsed in zip(group, parsed_group):
            results[index] = parsed
    if any(item is None for item in results):
        raise RuntimeError("isolated parser returned an incomplete document batch")
    return [item for item in results if item is not None]


def _decode_payload(content_base64: str) -> bytes:
    try:
        payload = base64.b64decode(content_base64, validate=True)
    except Exception as exc:
        raise ValueError("file content is not valid base64") from exc
    if not payload:
        raise ValueError("file is empty")
    if len(payload) > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds {MAX_FILE_BYTES // (1024 * 1024)} MB")
    return payload


def parse_document_bytes(*, filename: str, content: bytes) -> dict[str, Any]:
    safe_name = Path(str(filename or "uploaded-file")).name
    extension = Path(safe_name).suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        raise ValueError("supported file types are PDF, DOCX, XLSX and TXT")
    if not content:
        raise ValueError("file is empty")
    if len(content) > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds {MAX_FILE_BYTES // (1024 * 1024)} MB")

    digest = hashlib.sha256(content).hexdigest()
    if extension == ".txt":
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("TXT files must use UTF-8 encoding") from exc
        parser = "native-utf8"
        page_count = None
    else:
        temp_root = Path(os.environ.get("GUARDX_RUNTIME_TEMP", r"E:\GuardX\runtime\tmp"))
        temp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="guardx-docling-", dir=temp_root) as directory:
            input_path = Path(directory) / safe_name
            input_path.write_bytes(content)
            result = _docling_converter().convert(input_path)
            text = result.document.export_to_markdown()
            page_count = len(getattr(result.document, "pages", {}) or {}) or None
        parser = "docling"

    normalized = _normalize_text(text)
    if not normalized:
        raise ValueError(f"{safe_name} produced no extractable text")
    return {
        "source": safe_name,
        "text": normalized,
        "manifest": {
            "filename": safe_name,
            "extension": extension,
            "mime_family": extension.removeprefix("."),
            "sha256": digest,
            "bytes": len(content),
            "characters": len(normalized),
            "page_count": page_count,
            "parser": parser,
        },
    }


def parse_file_payloads(files: list[Any]) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    if not files:
        raise ValueError("at least one file is required")
    if len(files) > 12:
        raise ValueError("at most 12 files may be parsed in one request")
    raw_items = []
    for item in files:
        filename = str(getattr(item, "filename", "") or "uploaded-file")
        encoded = str(getattr(item, "content_base64", "") or "")
        raw_items.append({"filename": filename, "content": _decode_payload(encoded)})
    parsed_items = parse_documents_isolated(raw_items)
    documents = [{"source": parsed["source"], "text": parsed["text"]} for parsed in parsed_items]
    manifest = [parsed["manifest"] for parsed in parsed_items]
    return documents, manifest
