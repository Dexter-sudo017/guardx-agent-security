from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from pathlib import Path
from typing import Any


BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parents[2]
OUT_JSON = PROJECT_ROOT / "evidence" / "benchmark_traceability_matrix.json"
OUT_MD = PROJECT_ROOT / "team" / "zzh" / "experiments" / f"benchmark_traceability_matrix_{date.today().isoformat()}.md"


def _load(rel: str) -> dict[str, Any]:
    path = PROJECT_ROOT / rel
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(rel: str) -> str:
    path = PROJECT_ROOT / rel
    if not path.is_file():
        return ""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evidence(rel: str, role: str) -> dict[str, Any]:
    path = PROJECT_ROOT / rel
    return {
        "path": rel,
        "role": role,
        "exists": path.exists(),
        "sha256": _sha(rel) if path.is_file() else "",
    }


def _float(value: Any) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def _int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def _pct(value: Any) -> str:
    try:
        return f"{float(value) * 100:.2f}%"
    except Exception:
        return "n/a"


def _method_names(payload: dict[str, Any]) -> list[str]:
    methods = payload.get("methods")
    if isinstance(methods, dict):
        return sorted(str(name) for name in methods)
    if isinstance(methods, list):
        return sorted(
            str(item.get("method"))
            for item in methods
            if isinstance(item, dict) and item.get("method")
        )
    complete = payload.get("complete_methods")
    if isinstance(complete, list):
        return sorted(str(item) for item in complete)
    return []


def _method_row(payload: dict[str, Any], name: str) -> dict[str, Any]:
    methods = payload.get("methods")
    if isinstance(methods, dict):
        row = methods.get(name)
        return row if isinstance(row, dict) else {}
    if isinstance(methods, list):
        for row in methods:
            if isinstance(row, dict) and row.get("method") == name:
                return row
    return {}


def _ledger_rows() -> dict[str, dict[str, Any]]:
    ledger = _load("evidence/official_evaluator_reproducibility_ledger.json")
    rows = ledger.get("rows") if isinstance(ledger.get("rows"), list) else []
    return {
        str(row.get("benchmark")): row
        for row in rows
        if isinstance(row, dict) and row.get("benchmark")
    }


def _parity_rows() -> dict[str, dict[str, Any]]:
    parity = _load("evidence/official_evaluator_parity_matrix.json")
    rows = parity.get("rows") if isinstance(parity.get("rows"), list) else []
    return {
        str(row.get("benchmark")): row
        for row in rows
        if isinstance(row, dict) and row.get("benchmark")
    }


def _row_ready(row: dict[str, Any]) -> bool:
    return (
        row.get("case_count", 0) > 0
        and row.get("official_leaderboard_score") is False
        and row.get("raw_prompt_rendered") is False
        and row.get("real_private_data_rendered") is False
        and all(item.get("exists") for item in row.get("evidence_files") or [])
        and bool(row.get("evaluation_boundary"))
    )


def _build_rows() -> list[dict[str, Any]]:
    ledger = _ledger_rows()
    parity = _parity_rows()
    same = _load("evidence/submission_same_batch_1079_ablation_2026-07-01.json")
    same_methods = _method_names(same)
    default_method = str(same.get("default_profile") or "")
    default_row = _method_row(same, default_method)
    deepseek_row = _method_row(same, "deepseek_judge")
    hf_row = _method_row(same, "hf_protectai_classifier")

    adv = _load("evidence/advbench_official_method_comparison.json")
    adv_methods = _method_names(adv)
    adv_guardx = _method_row(adv, default_method)
    adv_best = adv.get("best_low_review_method") if isinstance(adv.get("best_low_review_method"), dict) else {}
    adv_ledger = ledger.get("AdvBenchMethods") or ledger.get("AdvBench") or {}
    adv_parity = parity.get("AdvBench") or {}

    jbb = _load("evidence/jailbreakbench_official_method_comparison.json")
    jbb_methods = _method_names(jbb)
    jbb_best = jbb.get("best_recall_method") if isinstance(jbb.get("best_recall_method"), dict) else {}
    jbb_ledger = ledger.get("JailbreakBenchMethods") or ledger.get("JailbreakBench") or {}
    jbb_routing = ledger.get("JailbreakBenchRouting") or {}
    jbb_completion = ledger.get("JailbreakBenchCompletionScorer") or {}
    jbb_parity = parity.get("JailbreakBench") or {}

    harm_ledger = ledger.get("HarmBench") or {}
    harm_adv = ledger.get("HarmAdvCompletionScorer") or {}
    harm_step3 = ledger.get("HarmBenchStep3ImporterPreflight") or ledger.get("HarmBenchStep3Manifest") or {}
    harm_pair = ledger.get("HarmBench+XSTest") or {}
    harm_parity = parity.get("HarmBench") or {}

    xstest = ledger.get("XSTest") or {}
    strong_adapter = _load("evidence/strongreject_guardx_official_adapter.json")
    strong_scorer = _load("evidence/strongreject_official_compatible_scorer.json")
    strong_adapter_summary = strong_adapter.get("summary") if isinstance(strong_adapter.get("summary"), dict) else {}
    strong_scorer_summary = strong_scorer.get("summary") if isinstance(strong_scorer.get("summary"), dict) else {}

    agent = _load("evidence/agentdojo_injecagent_task_graph_replay_alignment.json")
    agent_summary = agent.get("summary") if isinstance(agent.get("summary"), dict) else {}
    agent_ledger = ledger.get("AgentDojo/InjecAgent") or {}

    vlm = _load("evidence/vlm_multi_image_provider_benchmark.json")
    vlm_summary = vlm.get("summary") if isinstance(vlm.get("summary"), dict) else {}

    rows = [
        {
            "row_id": "unified_1079_same_batch",
            "benchmark_family": "Unified external heldout",
            "benchmark_sources": ["JailbreakBench/HarmBench/AdvBench/XSTest-style", "AgentDojo/InjecAgent-style", "RAG/OCR/tool/plugin safe-abstraction cases"],
            "surface_layers": ["LLM input", "RAG", "OCR/VLM", "tool-output", "Agent action", "plugin/supply-chain"],
            "case_count": _int(same.get("max_method_case_count") or same.get("case_count")),
            "method_count": len(same_methods),
            "comparable_method_names": same_methods,
            "same_batch_comparable": True,
            "parity_level": "same_batch_external_evidence",
            "key_metrics": {
                "default_method": default_method,
                "default_attack_catch": default_row.get("attack_catch"),
                "default_fpr": default_row.get("fpr"),
                "default_benign_hard_block": default_row.get("benign_hard_block"),
                "judge_only_deepseek_attack_catch": deepseek_row.get("attack_catch"),
                "judge_only_deepseek_fpr": deepseek_row.get("fpr"),
                "hf_classifier_attack_catch": hf_row.get("attack_catch"),
                "hf_classifier_fpr": hf_row.get("fpr"),
            },
            "evidence_files": [
                _evidence("evidence/submission_same_batch_1079_ablation_2026-07-01.json", "same-batch method comparison"),
                _evidence("team/zzh/experiments/submission_evidence_index_2026-07-02.md", "submission evidence index"),
            ],
            "official_leaderboard_score": False,
            "raw_prompt_rendered": False,
            "real_private_data_rendered": False,
            "evaluation_boundary": "External benchmark evidence under one unified schema; not an official leaderboard result.",
            "remaining_gap": "Official platform scores still require upstream evaluator/submission portal receipts.",
        },
        {
            "row_id": "advbench_method_trace",
            "benchmark_family": "AdvBench",
            "benchmark_sources": ["llm-attacks/AdvBench harmful goals"],
            "surface_layers": ["LLM input"],
            "case_count": _int(adv.get("case_count") or (adv_ledger.get("metrics") or {}).get("case_count")),
            "method_count": len(adv_methods),
            "comparable_method_names": adv_methods,
            "same_batch_comparable": True,
            "parity_level": (adv_parity.get("current_adapter") or {}).get("parity_level") or "official-style method comparison",
            "key_metrics": {
                "guardx_attack_catch": adv_guardx.get("attack_catch"),
                "best_low_review_method": adv_best.get("method"),
                "best_low_review_attack_catch": adv_best.get("attack_catch"),
                "best_low_review_fpr": adv_best.get("fpr"),
                "runtime_vs_routed_delta": (adv_ledger.get("metrics") or {}).get("routed_vs_runtime_attack_catch_delta"),
            },
            "evidence_files": [
                _evidence("evidence/advbench_official_method_comparison.json", "AdvBench same-batch method comparison"),
                _evidence("evidence/advbench_local_official_reproduction.json", "AdvBench local official-style reproduction"),
                _evidence("evidence/official_evaluator_parity_matrix.json", "official evaluator parity matrix"),
            ],
            "official_leaderboard_score": False,
            "raw_prompt_rendered": False,
            "real_private_data_rendered": False,
            "evaluation_boundary": "AdvBench rows are compared with the same method schema; target text remains hash-only in public artifacts.",
            "remaining_gap": (adv_parity.get("remaining_gap") or "Official-style scoring still needs upstream/target-model evaluator receipt."),
        },
        {
            "row_id": "jailbreakbench_method_trace",
            "benchmark_family": "JailbreakBench",
            "benchmark_sources": ["JailbreakBench/JBB-Behaviors"],
            "surface_layers": ["LLM input"],
            "case_count": _int(jbb.get("case_count") or (jbb_ledger.get("metrics") or {}).get("case_count")),
            "method_count": len(jbb_methods),
            "comparable_method_names": jbb_methods,
            "same_batch_comparable": True,
            "parity_level": (jbb_parity.get("current_adapter") or {}).get("parity_level") or "local official behavior-set reproduction",
            "key_metrics": {
                "best_recall_method": jbb_best.get("method"),
                "best_recall_attack_catch": jbb_best.get("attack_catch"),
                "routing_best_low_hard_block_provider": (jbb_routing.get("metrics") or {}).get("best_low_hard_block_provider"),
                "completion_scorer_unsafe_rate": (jbb_completion.get("metrics") or {}).get("unsafe_completion_rate"),
            },
            "evidence_files": [
                _evidence("evidence/jailbreakbench_local_official_reproduction.json", "JailbreakBench local official reproduction"),
                _evidence("evidence/jailbreakbench_official_method_comparison.json", "JailbreakBench same-batch method comparison"),
                _evidence("evidence/jailbreakbench_completion_scorer_smoke.json", "JailbreakBench completion scorer smoke"),
            ],
            "official_leaderboard_score": False,
            "raw_prompt_rendered": False,
            "real_private_data_rendered": False,
            "evaluation_boundary": "Local official behavior-set evidence plus same-batch method comparison; no leaderboard submission is claimed.",
            "remaining_gap": (jbb_parity.get("remaining_gap") or "Need upstream completion/evaluator leaderboard route for official score."),
        },
        {
            "row_id": "harmbench_step3_trace",
            "benchmark_family": "HarmBench",
            "benchmark_sources": ["Center for AI Safety HarmBench behaviors", "HarmBench Step-3 completion shape"],
            "surface_layers": ["LLM input", "LLM output"],
            "case_count": _int((harm_ledger.get("metrics") or {}).get("case_count") or (harm_step3.get("metrics") or {}).get("selected_behavior_count")),
            "method_count": _int((harm_pair.get("metrics") or {}).get("method_count")),
            "comparable_method_names": ["runtime-only", "judge-only", "policy-routed", "completion-scorer-smoke"],
            "same_batch_comparable": True,
            "parity_level": (harm_parity.get("current_adapter") or {}).get("parity_level") or "local official reproduction plus Step-3 manifest",
            "key_metrics": {
                "local_official_attack_catch": (harm_ledger.get("metrics") or {}).get("attack_catch"),
                "completion_scorer_unsafe_rate": (harm_adv.get("metrics") or {}).get("harmbench_unsafe_completion_rate"),
                "step3_preflight_status": (harm_step3.get("metrics") or {}).get("status"),
                "upstream_official_classifier_invoked": False,
                "step3_importer_explicit_flag_supported": (harm_step3.get("metrics") or {}).get("importer_explicit_classifier_invoked_true"),
            },
            "evidence_files": [
                _evidence("evidence/harmbench_official_completion_manifest.json", "HarmBench Step-3 completion manifest"),
                _evidence("evidence/harmbench_step3_importer_preflight.json", "HarmBench Step-3 importer preflight"),
                _evidence("evidence/harm_adv_completion_scorer_smoke.json", "HarmBench/AdvBench completion scorer smoke"),
                _evidence("evidence/official_evaluator_reproducibility_ledger.json", "official evaluator reproducibility ledger"),
            ],
            "official_leaderboard_score": False,
            "raw_prompt_rendered": False,
            "real_private_data_rendered": False,
            "evaluation_boundary": "Step-3 input shape and importer are preflighted; upstream official classifier output is not claimed until imported.",
            "remaining_gap": (harm_parity.get("remaining_gap") or "Need upstream HarmBench classifier/evaluator output for official leaderboard-like claim."),
        },
        {
            "row_id": "fpr_boundary_trace",
            "benchmark_family": "XSTest / StrongREJECT",
            "benchmark_sources": ["XSTest", "StrongREJECT"],
            "surface_layers": ["LLM input", "LLM output"],
            "case_count": _int((xstest.get("metrics") or {}).get("case_count")) + _int(strong_adapter_summary.get("case_count")),
            "method_count": 3,
            "comparable_method_names": ["XSTest safe route", "StrongREJECT GuardX adapter", "StrongREJECT compatible scorer"],
            "same_batch_comparable": False,
            "parity_level": "official-compatible false-positive/refusal-boundary evidence",
            "key_metrics": {
                "xstest_safe_fpr": (xstest.get("metrics") or {}).get("safe_fpr"),
                "xstest_safe_hard_block": (xstest.get("metrics") or {}).get("safe_hard_block_rate"),
                "strongreject_risk_signal": strong_adapter_summary.get("risk_signal_detected_rate"),
                "strongreject_scorer_parse_ok": strong_scorer_summary.get("parse_ok_rate"),
            },
            "evidence_files": [
                _evidence("evidence/official_evaluator_adapters/xstest_adapter_manifest.json", "XSTest official-style adapter manifest"),
                _evidence("evidence/strongreject_guardx_official_adapter.json", "StrongREJECT GuardX adapter"),
                _evidence("evidence/strongreject_official_compatible_scorer.json", "StrongREJECT compatible scorer"),
            ],
            "official_leaderboard_score": False,
            "raw_prompt_rendered": False,
            "real_private_data_rendered": False,
            "evaluation_boundary": "False-positive and refusal-boundary evidence is kept separate from harmful-request catch metrics.",
            "remaining_gap": "StrongREJECT cloud autograder is not claimed as official unless explicitly invoked under official protocol.",
        },
        {
            "row_id": "agentdojo_injecagent_trace",
            "benchmark_family": "AgentDojo / InjecAgent",
            "benchmark_sources": ["AgentDojo-style task graph", "InjecAgent-style indirect injection/tool observation"],
            "surface_layers": ["RAG", "tool-output", "Agent action", "plugin/supply-chain"],
            "case_count": _int(agent_summary.get("case_count")),
            "method_count": 1,
            "comparable_method_names": ["GuardX action guard replay alignment"],
            "same_batch_comparable": True,
            "parity_level": "task-graph replay alignment",
            "key_metrics": {
                "action_node_count": agent_summary.get("action_node_count"),
                "alignment_pass_rate": agent_summary.get("alignment_pass_rate"),
                "security_block_rate": agent_summary.get("security_block_rate"),
                "utility_allow_rate": agent_summary.get("utility_allow_rate"),
                "benign_block_rate": agent_summary.get("benign_block_rate"),
                "ledger_alignment": (agent_ledger.get("metrics") or {}).get("alignment_pass_rate"),
            },
            "evidence_files": [
                _evidence("evidence/agentdojo_injecagent_official_task_graph_mapping.json", "Agent task graph mapping"),
                _evidence("evidence/agentdojo_injecagent_task_graph_replay_alignment.json", "Agent task graph replay alignment"),
            ],
            "official_leaderboard_score": False,
            "raw_prompt_rendered": False,
            "real_private_data_rendered": False,
            "evaluation_boundary": "Task graph is official-style/proxy evidence for cross-layer Agent behavior, not official AgentDojo leaderboard output.",
            "remaining_gap": "A full upstream AgentDojo/InjecAgent environment run would be stronger if time and environment permit.",
        },
        {
            "row_id": "vlm_ocr_trace",
            "benchmark_family": "VLM/OCR multi-image",
            "benchmark_sources": ["DocVQA/FUNSD/CORD-style document images", "synthetic low-contrast hidden-instruction images"],
            "surface_layers": ["OCR/VLM", "context boundary", "privacy"],
            "case_count": _int(vlm_summary.get("image_count")),
            "method_count": _int(vlm_summary.get("provider_row_count")),
            "comparable_method_names": ["OCR-only", "VLM provider caption/judge", "GuardX OCR+VLM routed"],
            "same_batch_comparable": True,
            "parity_level": "multi-provider OCR/VLM evidence",
            "key_metrics": {
                "provider_success_rate": vlm_summary.get("provider_success_rate"),
                "image_level_attack_catch": vlm_summary.get("image_level_attack_catch"),
                "image_level_fpr_review_or_block": vlm_summary.get("image_level_fpr_review_or_block"),
                "image_level_hard_block_fpr": vlm_summary.get("image_level_hard_block_fpr"),
                "ocr_vlm_disagreement": vlm_summary.get("ocr_vlm_risk_hint_disagreement_rate"),
            },
            "evidence_files": [
                _evidence("evidence/vlm_multi_image_provider_benchmark.json", "VLM/OCR multi-image provider benchmark"),
                _evidence("evidence/ocr_samples/real_ocr_6image_merged_manifest.json", "real OCR six-image merged manifest"),
            ],
            "official_leaderboard_score": False,
            "raw_prompt_rendered": False,
            "real_private_data_rendered": False,
            "evaluation_boundary": "This validates hidden-instruction/privacy-risk routing for OCR/VLM inputs; it is not a general VLM jailbreak leaderboard.",
            "remaining_gap": "Add official VLM jailbreak datasets only if a safe public evaluator route is available.",
        },
    ]
    for row in rows:
        row["ready"] = _row_ready(row)
    return rows


def build_payload() -> dict[str, Any]:
    rows = _build_rows()
    distinct_methods = sorted(
        {
            method
            for row in rows
            for method in row.get("comparable_method_names", [])
            if isinstance(method, str) and method
        }
    )
    evidence_files = sorted(
        {
            item["path"]
            for row in rows
            for item in row.get("evidence_files", [])
            if isinstance(item, dict) and item.get("path")
        }
    )
    missing_evidence = [
        item
        for row in rows
        for item in row.get("evidence_files", [])
        if isinstance(item, dict) and not item.get("exists")
    ]
    ready = (
        len(rows) >= 7
        and all(row.get("ready") for row in rows)
        and not missing_evidence
        and all(row.get("official_leaderboard_score") is False for row in rows)
        and all(row.get("raw_prompt_rendered") is False for row in rows)
        and all(row.get("real_private_data_rendered") is False for row in rows)
    )
    return {
        "schema_version": "guardx-benchmark-traceability-matrix-v1",
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "ready": ready,
        "row_count": len(rows),
        "ready_row_count": sum(1 for row in rows if row.get("ready")),
        "benchmark_family_count": len({row["benchmark_family"] for row in rows}),
        "distinct_method_count": len(distinct_methods),
        "distinct_methods": distinct_methods,
        "evidence_file_count": len(evidence_files),
        "evidence_files": evidence_files,
        "missing_evidence_count": len(missing_evidence),
        "missing_evidence": missing_evidence,
        "same_batch_or_boundary_explained": all(row.get("same_batch_comparable") or row.get("evaluation_boundary") for row in rows),
        "official_leaderboard_score": False,
        "raw_prompt_rendered": False,
        "real_private_data_rendered": False,
        "claim_boundary": (
            "Traceability matrix for benchmark/method/source alignment. It proves evidence coverage and claim boundaries, "
            "but it is not an official leaderboard score or platform receipt."
        ),
        "rows": rows,
    }


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# GuardX Benchmark Traceability Matrix",
        "",
        f"- Updated: `{date.today().isoformat()}`",
        f"- Ready: `{payload['ready']}`",
        f"- Rows: `{payload['row_count']}`",
        f"- Ready rows: `{payload['ready_row_count']}`",
        f"- Benchmark families: `{payload['benchmark_family_count']}`",
        f"- Distinct methods/signals: `{payload['distinct_method_count']}`",
        f"- Missing evidence: `{payload['missing_evidence_count']}`",
        f"- Official leaderboard score claimed: `{payload['official_leaderboard_score']}`",
        f"- Raw prompt rendered: `{payload['raw_prompt_rendered']}`",
        f"- Real private data rendered: `{payload['real_private_data_rendered']}`",
        f"- Claim boundary: {payload['claim_boundary']}",
        "",
        "## Matrix",
        "",
        "| row | benchmark | cases | methods/signals | comparable? | key metric | boundary | remaining gap |",
        "| --- | --- | ---: | ---: | --- | --- | --- | --- |",
    ]
    for row in payload["rows"]:
        metrics = row.get("key_metrics") if isinstance(row.get("key_metrics"), dict) else {}
        preferred = (
            f"catch={_pct(metrics.get('default_attack_catch') or metrics.get('guardx_attack_catch') or metrics.get('best_low_review_attack_catch') or metrics.get('best_recall_attack_catch') or metrics.get('image_level_attack_catch'))}; "
            f"FPR={_pct(metrics.get('default_fpr') or metrics.get('best_low_review_fpr') or metrics.get('xstest_safe_fpr') or metrics.get('image_level_fpr_review_or_block') or metrics.get('benign_block_rate'))}"
        )
        lines.append(
            f"| `{_cell(row['row_id'])}` | {_cell(row['benchmark_family'])} | {row['case_count']} | {row['method_count']} | "
            f"`{row['same_batch_comparable']}` | {_cell(preferred)} | {_cell(row['evaluation_boundary'])} | {_cell(row['remaining_gap'])} |"
        )
    lines.extend(
        [
            "",
            "## Evidence Files",
            "",
            "| file |",
            "| --- |",
        ]
    )
    for rel in payload["evidence_files"]:
        lines.append(f"| `{_cell(rel)}` |")
    lines.extend(
        [
            "",
            "## Reading",
            "",
            "- This matrix is the answer to: `are all methods being compared on the same benchmark surface?`",
            "- The `same_batch_comparable` column identifies rows where the method set runs over the same case subset; rows that are not same-batch are kept as boundary/adapter evidence instead of being mixed into a single leaderboard-like score.",
            "- Public artifacts remain hash-only/aggregate: no raw high-risk prompt, official target text, real private data, API key, or official submission receipt is rendered here.",
            "- The matrix deliberately preserves gaps such as upstream classifier output or official leaderboard submission, so the defense story stays scientifically honest.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    payload = build_payload()
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text(_markdown(payload), encoding="utf-8")
    print(
        json.dumps(
            {
                "out": OUT_JSON.relative_to(PROJECT_ROOT).as_posix(),
                "report": OUT_MD.relative_to(PROJECT_ROOT).as_posix(),
                "ready": payload["ready"],
                "row_count": payload["row_count"],
                "method_count": payload["distinct_method_count"],
                "missing_evidence": payload["missing_evidence_count"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if payload["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
