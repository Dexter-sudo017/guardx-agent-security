from __future__ import annotations

import json
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parents[2]


REQUIRED_EVIDENCE = [
    "evidence/final_submission_gate.json",
    "evidence/competition_submission_readiness_audit.json",
    "evidence/benchmark_traceability_matrix.json",
    "evidence/submission_same_batch_1079_ablation_2026-07-01.json",
    "evidence/input_specialist_v2b_balanced_t0725_summary.json",
    "evidence/agent_vlm_realism_cases_latest.json",
    "evidence/vlm_multi_image_provider_benchmark.json",
    "evidence/agentdojo_injecagent_task_graph_replay_alignment.json",
]


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    checks: list[dict] = []
    failed = 0

    for rel in REQUIRED_EVIDENCE:
        path = PROJECT_ROOT / rel
        ok = path.is_file()
        detail = "present" if ok else "missing"
        if ok:
            try:
                _load(path)
            except Exception as exc:
                ok = False
                detail = f"invalid json: {exc}"
        checks.append({"item": rel, "status": "pass" if ok else "fail", "detail": detail})
        failed += 0 if ok else 1

    result = {
        "schema_version": "guardx-final-submission-gate-v1",
        "status": "pass" if failed == 0 else "fail",
        "check_count": len(checks),
        "failed_count": failed,
        "checks": checks,
        "claim_boundary": "This gate checks local source package evidence only and does not claim official platform acceptance or award result.",
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
