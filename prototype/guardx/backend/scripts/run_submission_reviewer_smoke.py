from __future__ import annotations

import json
import sys
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parents[2]


REQUIRED_DIRS = [
    "attack_cases",
    "configs",
    "evidence",
    "prototype/guardx/backend/app",
    "prototype/guardx/backend/scripts",
    "prototype/guardx/backend/tests",
    "prototype/guardx/configs",
]

REQUIRED_FILES = [
    "README.md",
    "prototype/guardx/backend/app/main.py",
    "prototype/guardx/backend/requirements-ci.txt",
    "prototype/guardx/backend/scripts/smoke_eval.py",
    "prototype/guardx/backend/scripts/run_final_submission_gate.py",
    "prototype/guardx/backend/scripts/run_submission_reviewer_smoke.py",
]

REQUIRED_EVIDENCE = {
    "evidence/final_submission_gate.json": ("status", "pass"),
    "evidence/competition_submission_readiness_audit.json": ("ready", True),
    "evidence/benchmark_traceability_matrix.json": ("ready", True),
    "evidence/claim_defense_matrix.json": ("ready", True),
    "evidence/reviewer_reproduction_commands.json": ("ready", True),
    "evidence/official_evaluator_reproducibility_ledger.json": ("required_files_ok", True),
}

FORBIDDEN_NAMES = {
    ".ai",
    ".git",
    "docs",
    "design",
    "references",
    "planning",
    "team",
    "submission_artifacts",
    "PROJECT_INDEX.md",
    "SOURCE_MANIFEST.txt",
    "SOURCE_MANIFEST.json",
}

FORBIDDEN_EXTENSIONS = {".docx", ".pdf", ".pptx", ".zip", ".7z", ".rar", ".db", ".sqlite", ".sqlite3", ".pyc", ".tmp"}


def _load_json(rel: str) -> dict:
    path = PROJECT_ROOT / rel
    return json.loads(path.read_text(encoding="utf-8"))


def _record(results: list[tuple[str, bool, str]], item: str, ok: bool, detail: str) -> None:
    results.append((item, ok, detail))


def main() -> int:
    results: list[tuple[str, bool, str]] = []

    for rel in REQUIRED_DIRS:
        _record(results, f"dir:{rel}", (PROJECT_ROOT / rel).is_dir(), rel)

    for rel in REQUIRED_FILES:
        _record(results, f"file:{rel}", (PROJECT_ROOT / rel).is_file(), rel)

    for rel, (key, expected) in REQUIRED_EVIDENCE.items():
        path = PROJECT_ROOT / rel
        if not path.is_file():
            _record(results, f"evidence:{rel}", False, "missing")
            continue
        try:
            data = _load_json(rel)
        except Exception as exc:
            _record(results, f"evidence:{rel}", False, f"invalid json: {exc}")
            continue
        ok = data.get(key) == expected
        if rel.endswith("final_submission_gate.json"):
            ok = ok and int(data.get("failed_count", 1)) == 0
        if rel.endswith("benchmark_traceability_matrix.json"):
            ok = ok and int(data.get("missing_evidence_count", 1)) == 0
        if rel.endswith("claim_defense_matrix.json"):
            ok = ok and int(data.get("unresolved_count", 1)) == 0
        _record(results, f"evidence:{rel}", ok, f"{key}={data.get(key)!r}")

    bad_paths: list[str] = []
    for path in PROJECT_ROOT.rglob("*"):
        rel = path.relative_to(PROJECT_ROOT).as_posix()
        name = path.name
        lower = rel.lower()
        if name in FORBIDDEN_NAMES:
            bad_paths.append(rel)
            continue
        if path.is_file() and path.suffix.lower() in FORBIDDEN_EXTENSIONS:
            bad_paths.append(rel)
            continue
    _record(results, "package:forbidden_artifacts", not bad_paths, ", ".join(bad_paths[:20]) if bad_paths else "clean")

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    for item, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'} {item}: {detail}")
    print(f"summary: {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
