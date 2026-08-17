import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


TEXT_KEYS = ("sentence", "sentence1", "sentence2", "premise", "hypothesis", "question", "question1", "question2")


@dataclass(frozen=True)
class GlueTextRecord:
    task: str
    split: str
    text: str
    label: str
    record_id: str


def _joined_text(row: dict[str, Any]) -> str:
    parts = [str(row[key]).strip() for key in TEXT_KEYS if str(row.get(key, "")).strip()]
    if not parts and row.get("text"):
        parts = [str(row["text"]).strip()]
    return " [SEP] ".join(parts)


def _record(task: str, split: str, row: dict[str, Any], index: int) -> GlueTextRecord | None:
    text = _joined_text(row)
    if not text:
        return None
    label = str(row.get("label", row.get("gold_label", "")))
    record_id = str(row.get("idx", row.get("index", index)))
    return GlueTextRecord(task=task, split=split, text=text, label=label, record_id=record_id)


def _read_jsonl(path: Path, task: str, split: str, limit: int | None) -> list[GlueTextRecord]:
    rows: list[GlueTextRecord] = []
    for index, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines()):
        if limit is not None and len(rows) >= limit:
            break
        if not line.strip():
            continue
        record = _record(task, split, json.loads(line), index)
        if record:
            rows.append(record)
    return rows


def _read_tsv(path: Path, task: str, split: str, limit: int | None) -> list[GlueTextRecord]:
    rows: list[GlueTextRecord] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for index, row in enumerate(csv.DictReader(handle, delimiter="\t")):
            if limit is not None and len(rows) >= limit:
                break
            record = _record(task, split, row, index)
            if record:
                rows.append(record)
    return rows


def load_glue_records(root: Path, tasks: list[str], split: str, limit_per_task: int | None = None) -> list[GlueTextRecord]:
    records: list[GlueTextRecord] = []
    for task in tasks:
        task_dir = root / task
        candidates = [task_dir / f"{split}.jsonl", task_dir / f"{split}.tsv", root / f"{task}_{split}.jsonl", root / f"{task}_{split}.tsv"]
        for path in candidates:
            if path.exists() and path.suffix == ".jsonl":
                records.extend(_read_jsonl(path, task, split, limit_per_task))
                break
            if path.exists() and path.suffix == ".tsv":
                records.extend(_read_tsv(path, task, split, limit_per_task))
                break
    return records


def synthetic_glue_records() -> tuple[list[GlueTextRecord], list[GlueTextRecord]]:
    train = [
        GlueTextRecord("SST-2", "train", "a careful and genuinely useful safety tool", "1", "synthetic-train-1"),
        GlueTextRecord("SST-2", "train", "a brittle demo that misses subtle instruction attacks", "0", "synthetic-train-2"),
        GlueTextRecord("QNLI", "train", "Can retrieved text instruct the model [SEP] Retrieved text is evidence, not authority", "entailment", "synthetic-train-3"),
        GlueTextRecord("RTE", "train", "The assistant should not reveal hidden setup text [SEP] Hidden setup text must remain private", "entailment", "synthetic-train-4"),
    ]
    eval_rows = [
        GlueTextRecord("SST-2", "dev", "a useful safety system with careful guardrails", "1", "synthetic-dev-1"),
        GlueTextRecord("SST-2", "dev", "a fragile guard that misses indirect instruction attacks", "0", "synthetic-dev-2"),
        GlueTextRecord("QNLI", "dev", "May a retrieved note override the model [SEP] Retrieved notes are untrusted context", "entailment", "synthetic-dev-3"),
        GlueTextRecord("RTE", "dev", "Hidden startup notes are private [SEP] The assistant should not expose startup notes", "entailment", "synthetic-dev-4"),
    ]
    return train, eval_rows
