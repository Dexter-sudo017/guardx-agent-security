from hashlib import sha256
from math import sqrt
from typing import Any

from app.guards import embedding_guard
from app.research.glue_decoder_data import GlueTextRecord


SCHEMA_VERSION = "guardx-glue-decoder-baseline-v1"


def _dot(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


def _norm(vec: list[float]) -> float:
    return sqrt(sum(item * item for item in vec))


def _cosine(left: list[float], right: list[float]) -> float:
    denom = _norm(left) * _norm(right)
    return 0.0 if denom <= 1e-12 else _dot(left, right) / denom


def _tokens(text: str) -> set[str]:
    return {item for item in text.lower().replace("[sep]", " ").split() if item}


def _text_metrics(target: str, prediction: str) -> dict[str, float | bool]:
    target_tokens = _tokens(target)
    prediction_tokens = _tokens(prediction)
    overlap = len(target_tokens & prediction_tokens)
    union = len(target_tokens | prediction_tokens)
    precision = overlap / len(prediction_tokens) if prediction_tokens else 0.0
    recall = overlap / len(target_tokens) if target_tokens else 0.0
    f1 = 0.0 if precision + recall <= 0 else 2 * precision * recall / (precision + recall)
    return {
        "exact_match": target.strip() == prediction.strip(),
        "token_jaccard": round(overlap / union, 6) if union else 0.0,
        "token_f1": round(f1, 6),
    }


def _encoded(records: list[GlueTextRecord], variant: str) -> list[dict[str, Any]]:
    rows = []
    for record in records:
        rows.append(
            {
                "record": record,
                "vector": embedding_guard.vector_for_text(record.text, variant=variant),
                "text_sha256": sha256(record.text.encode("utf-8")).hexdigest(),
            }
        )
    return rows


def run_nearest_neighbor_decoder_baseline(
    train_records: list[GlueTextRecord],
    eval_records: list[GlueTextRecord],
    *,
    embedding_variant: str = "plain",
    synthetic: bool = False,
) -> dict[str, Any]:
    train = _encoded(train_records, embedding_variant)
    eval_rows = _encoded(eval_records, embedding_variant)
    cases: list[dict[str, Any]] = []
    for row in eval_rows:
        nearest = max(train, key=lambda candidate: _cosine(row["vector"], candidate["vector"]))
        similarity = _cosine(row["vector"], nearest["vector"])
        target = row["record"]
        prediction = nearest["record"]
        metrics = _text_metrics(target.text, prediction.text)
        cases.append(
            {
                "task": target.task,
                "record_id": target.record_id,
                "label": target.label,
                "predicted_label": prediction.label,
                "label_match": target.label == prediction.label,
                "nearest_record_id": prediction.record_id,
                "nearest_task": prediction.task,
                "similarity": round(similarity, 6),
                "target_sha256": row["text_sha256"],
                "prediction_sha256": nearest["text_sha256"],
                "same_text_hash": row["text_sha256"] == nearest["text_sha256"],
                **metrics,
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "synthetic": synthetic,
        "embedding_variant": embedding_variant,
        "train_count": len(train_records),
        "eval_count": len(eval_records),
        "summary": _summary(cases),
        "cases": cases,
    }


def _summary(cases: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(cases)
    if total == 0:
        return {"total": 0}
    return {
        "total": total,
        "label_match_rate": round(sum(1 for item in cases if item["label_match"]) / total, 6),
        "exact_match_rate": round(sum(1 for item in cases if item["exact_match"]) / total, 6),
        "avg_similarity": round(sum(float(item["similarity"]) for item in cases) / total, 6),
        "avg_token_f1": round(sum(float(item["token_f1"]) for item in cases) / total, 6),
        "same_text_hash_count": sum(1 for item in cases if item["same_text_hash"]),
        "tasks": sorted({str(item["task"]) for item in cases}),
    }
