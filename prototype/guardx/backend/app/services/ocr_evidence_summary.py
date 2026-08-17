from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[5]
REAL_OCR_MANIFEST_PATH = PROJECT_ROOT / "evidence" / "ocr_samples" / "real_ocr_manifest.json"
TESSERACT_EXTENSION_MANIFEST_PATH = (
    PROJECT_ROOT / "evidence" / "ocr_samples" / "real_ocr_tesseract_extension_manifest.json"
)


def _short_hash(value: str) -> str:
    return value[:12] if value else ""


def _run_summary(record: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    return {
        "engine": run.get("engine"),
        "engine_version": run.get("engine_version", ""),
        "available": run.get("available", True),
        "ocr_output_path": run.get("ocr_output_path", ""),
        "ocr_output_sha256": run.get("ocr_output_sha256", ""),
        "ocr_output_short_hash": _short_hash(str(run.get("ocr_output_sha256", ""))),
        "rendered_image_sha256": record.get("render", {}).get("rendered_image_sha256", ""),
        "rendered_image_short_hash": _short_hash(str(record.get("render", {}).get("rendered_image_sha256", ""))),
    }


def _sample_summary(record: dict[str, Any]) -> dict[str, Any]:
    runs = [_run_summary(record, run) for run in record.get("ocr_runs", []) if isinstance(run, dict)]
    return {
        "sample_id": record.get("sample_id"),
        "image_id": record.get("image_id"),
        "expected_case_id": record.get("expected_case_id"),
        "synthetic": record.get("synthetic", True),
        "contains_real_pii": record.get("contains_real_pii", False),
        "rendered_image_path": record.get("render", {}).get("rendered_image_path", ""),
        "ocr_runs": runs,
    }


def build_ocr_evidence_summary(path: Path = REAL_OCR_MANIFEST_PATH) -> dict[str, Any]:
    if not path.exists():
        return {
            "schema_version": "guardx-ocr-evidence-summary-v1",
            "available": False,
            "manifest_path": str(path.relative_to(PROJECT_ROOT)),
            "engine_summary": {},
            "record_count": 0,
            "samples": [],
        }
    manifest = json.loads(path.read_text(encoding="utf-8"))
    samples = [_sample_summary(record) for record in manifest.get("records", []) if isinstance(record, dict)]
    extension_manifests = []
    if path == REAL_OCR_MANIFEST_PATH and TESSERACT_EXTENSION_MANIFEST_PATH.exists():
        extension = json.loads(TESSERACT_EXTENSION_MANIFEST_PATH.read_text(encoding="utf-8"))
        extension_samples = [
            _sample_summary(record) for record in extension.get("records", []) if isinstance(record, dict)
        ]
        samples.extend(extension_samples)
        extension_manifests.append(
            {
                "manifest_path": str(TESSERACT_EXTENSION_MANIFEST_PATH.relative_to(PROJECT_ROOT)),
                "engine_summary": extension.get("engine_summary", {}),
                "record_count": len(extension_samples),
            }
        )
    return {
        "schema_version": "guardx-ocr-evidence-summary-v1",
        "available": True,
        "manifest_path": str(path.relative_to(PROJECT_ROOT)),
        "extension_manifests": extension_manifests,
        "generated_at": manifest.get("generated_at", ""),
        "privacy_policy": manifest.get("privacy_policy", ""),
        "engine_summary": manifest.get("engine_summary", {}),
        "record_count": len(samples),
        "samples": samples,
    }
