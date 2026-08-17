from __future__ import annotations


STATIC_FIELDS = (
    "story_stage",
    "demo_claim",
    "attack_vector",
    "trust_boundary",
    "benchmark_family",
    "benchmark_task",
    "security_property",
)

EVIDENCE_FIELDS = (
    "evidence_refs",
    "ocr_engine",
    "ocr_engine_version",
    "ocr_output_path",
    "ocr_output_sha256",
    "rendered_image_sha256",
    "ocr_manifest_path",
    "ocr_disagreement",
)


def experiment_case_metadata(case: object) -> dict:
    metadata = {}
    for key in STATIC_FIELDS + EVIDENCE_FIELDS:
        default = {} if key == "ocr_disagreement" else ""
        value = getattr(case, key, default)
        if value:
            metadata[key] = value
    return metadata
