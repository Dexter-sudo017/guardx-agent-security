import json
from pathlib import Path
from typing import Any


SCHEMA_KIND_MAP = {
    "guardx-real-model-matrix-plan-v1": "real_model_matrix_plan",
    "guardx-embedding-ablation-v1": "embedding_ablation",
    "guardx-glue-decoder-baseline-v1": "glue_decoder_baseline",
    "guardx-decoder-probe-summary-v1": "decoder_probe",
    "guardx-competition-readiness-v1": "competition_readiness",
    "guardx-competition-gap-radar-v1": "competition_gap_radar",
    "guardx-model-feedback-loop-v1": "model_feedback_loop",
    "guardx-target-integration-replay-v1": "target_integration_replay",
    "guardx-demo-storyline-replay-v1": "demo_storyline_replay",
    "guardx-agent-end-to-end-replay-v1": "agent_end_to_end_replay",
    "guardx-real-executor-replay-v1": "real_executor_replay",
    "guardx-live-target-preflight-v1": "live_target_preflight",
    "guardx-live-target-readiness-v1": "live_target_readiness",
    "guardx-live-target-rehearsal-v1": "live_target_rehearsal",
    "guardx-public-benchmark-gate-v1": "public_benchmark_gate",
    "guardx-external-benchmark-evidence-v1": "external_benchmark_evidence",
    "guardx-adaptive-baseline-comparison-v1": "adaptive_baseline_comparison",
    "guardx-adaptive-external-baselines-v1": "adaptive_external_baselines",
    "guardx-layered-baseline-comparison-v1": "layered_baseline_comparison",
    "guardx-semantic-method-matrix-v1": "semantic_method_matrix",
    "guardx-local-lora-eval-v1": "local_lora_semantic_eval",
    "guardx-defense-action-ablation-v1": "defense_action_ablation",
    "guardx-judge-provider-healthcheck-v1": "judge_provider_healthcheck",
    "guardx-official-leaderboard-readiness-v1": "official_leaderboard_readiness",
    "guardx-vlm-provider-probe-v1": "vlm_provider_probe",
    "guardx-judge-aware-policy-profile-v1": "judge_aware_policy_profile",
    "guardx-unified-defense-ablation-v1": "unified_defense_ablation",
    "guardx-agent-vlm-realism-eval-v1": "agent_vlm_realism",
    "guardx-vlm-multi-provider-probe-v1": "vlm_multi_provider_probe",
    "guardx-vlm-multi-image-provider-benchmark-v1": "vlm_multi_image_provider_benchmark",
    "guardx-xstest-local-official-reproduction-v1": "xstest_local_official_reproduction",
    "guardx-harmbench-local-official-reproduction-v1": "harmbench_local_official_reproduction",
    "guardx-advbench-local-official-reproduction-v1": "advbench_local_official_reproduction",
    "guardx-jailbreakbench-local-official-reproduction-v1": "jailbreakbench_local_official_reproduction",
    "guardx-jailbreakbench-official-method-comparison-v1": "jailbreakbench_official_method_comparison",
    "guardx-jailbreakbench-judge-routing-ablation-v1": "jailbreakbench_judge_routing_ablation",
    "guardx-jailbreakbench-judge-routing-threshold-sweep-v1": "jailbreakbench_judge_routing_threshold_sweep",
    "guardx-jailbreakbench-completion-scorer-smoke-v1": "jailbreakbench_completion_scorer_smoke",
    "guardx-harm-adv-completion-scorer-smoke-v1": "harm_adv_completion_scorer_smoke",
    "guardx-harmbench-official-completion-manifest-v1": "harmbench_official_completion_manifest",
    "guardx-harmbench-step3-importer-preflight-v1": "harmbench_step3_importer_preflight",
    "guardx-harmbench-step3-result-guard-v1": "harmbench_step3_result_guard",
    "guardx-harmbench-official-step3-result-summary-v1": "harmbench_official_step3_result_summary",
    "guardx-harmbench-official-method-comparison-v1": "harmbench_official_method_comparison",
    "guardx-advbench-official-method-comparison-v1": "advbench_official_method_comparison",
    "guardx-official-judge-tradeoff-v1": "official_judge_tradeoff",
    "guardx-official-judge-routing-ablation-v1": "official_judge_routing_ablation",
    "guardx-agentdojo-injecagent-official-task-graph-mapping-v1": "agent_task_graph_mapping",
    "guardx-agentdojo-injecagent-task-graph-replay-alignment-v1": "agent_task_graph_replay_alignment",
    "guardx-agentdojo-injecagent-task-state-run-v1": "agent_task_state_harness",
    "guardx-official-evaluator-parity-matrix-v1": "official_evaluator_parity",
    "guardx-official-evaluator-reproducibility-ledger-v1": "official_evaluator_reproducibility_ledger",
    "guardx-official-evaluator-gap-closure-plan-v1": "official_evaluator_gap_closure_plan",
    "guardx-upstream-evaluator-runnable-checklist-v1": "upstream_evaluator_runnable_checklist",
    "guardx-upstream-evaluator-smoke-readiness-v1": "upstream_evaluator_smoke_readiness",
    "guardx-strongreject-official-autograder-preflight-v1": "strongreject_official_autograder_preflight",
    "guardx-strongreject-guardx-official-adapter-v1": "strongreject_guardx_official_adapter",
    "guardx-strongreject-official-compatible-scorer-v1": "strongreject_official_compatible_scorer",
    "guardx-lora-benign-recovery-dataset-v1": "lora_benign_recovery_dataset",
    "guardx-same-batch-unified-ablation-v1": "same_batch_unified_ablation",
    "guardx-unified-509-fine-grained-ablation-v1": "same_batch_unified_ablation",
    "guardx-lora-routing-delta-v1": "lora_routing_delta",
    "guardx-demo-flow-summary-v1": "demo_flow_summary",
    "guardx-final-submission-gate-v1": "final_submission_gate",
    "guardx-portal-rehearsal-v1": "portal_rehearsal",
    "guardx-submission-package-manifest-v1": "submission_package_manifest",
    "guardx-competition-submission-readiness-audit-v1": "competition_submission_readiness_audit",
    "guardx-claim-defense-matrix-v1": "claim_defense_matrix",
    "guardx-final-rehearsal-runbook-v1": "final_rehearsal_runbook",
    "guardx-official-submission-handoff-checklist-v1": "official_submission_handoff_checklist",
    "guardx-demo-recording-plan-v1": "demo_recording_plan",
    "guardx-final-submission-packet-cover-v1": "final_submission_packet_cover",
    "guardx-judge-rubric-scorecard-v1": "judge_rubric_scorecard",
    "guardx-benchmark-traceability-matrix-v1": "benchmark_traceability_matrix",
    "guardx-final-live-demo-rehearsal-scorecard-v1": "final_live_demo_rehearsal_scorecard",
    "guardx-evidence-readiness-board-v1": "evidence_readiness_board",
    "guardx-defense-evidence-notes-v1": "defense_evidence_notes",
    "guardx-presentation-freshness-check-v1": "presentation_freshness_check",
    "guardx-reviewer-reproduction-commands-v1": "reviewer_reproduction_commands",
    "guardx-public-archive-review-scan-v1": "public_archive_review_scan",
    "guardx-public-archive-reproduction-smoke-v1": "public_archive_reproduction_smoke",
}
NAME_KIND_RULES = [
    ("public_archive_reproduction_smoke", "public_archive_reproduction_smoke"),
    ("public_archive_review_scan", "public_archive_review_scan"),
    ("reviewer_reproduction_commands", "reviewer_reproduction_commands"),
    ("presentation_freshness_check", "presentation_freshness_check"),
    ("defense_evidence_notes", "defense_evidence_notes"),
    ("evidence_readiness_board", "evidence_readiness_board"),
    ("final_live_demo_rehearsal_scorecard", "final_live_demo_rehearsal_scorecard"),
    ("benchmark_traceability_matrix", "benchmark_traceability_matrix"),
    ("judge_rubric_scorecard", "judge_rubric_scorecard"),
    ("final_submission_packet_cover", "final_submission_packet_cover"),
    ("demo_recording_plan", "demo_recording_plan"),
    ("official_submission_handoff_checklist", "official_submission_handoff_checklist"),
    ("final_rehearsal_runbook", "final_rehearsal_runbook"),
    ("claim_defense_matrix", "claim_defense_matrix"),
    ("competition_submission_readiness_audit", "competition_submission_readiness_audit"),
    ("submission_package_manifest", "submission_package_manifest"),
    ("demo_flow_summary", "demo_flow_summary"),
    ("portal_rehearsal", "portal_rehearsal"),
    ("final_submission_gate", "final_submission_gate"),
    ("lora_routing_delta", "lora_routing_delta"),
    ("same_batch_unified_ablation", "same_batch_unified_ablation"),
    ("lora_benign_recovery", "lora_benign_recovery_dataset"),
    ("vlm_multi_provider", "vlm_multi_provider_probe"),
    ("vlm_multi_image", "vlm_multi_image_provider_benchmark"),
    ("xstest_local_official", "xstest_local_official_reproduction"),
    ("advbench_local_official", "advbench_local_official_reproduction"),
    ("jailbreakbench_local_official", "jailbreakbench_local_official_reproduction"),
    ("jailbreakbench_official_method_comparison", "jailbreakbench_official_method_comparison"),
    ("jailbreakbench_judge_routing_ablation", "jailbreakbench_judge_routing_ablation"),
    ("jailbreakbench_judge_routing_threshold_sweep", "jailbreakbench_judge_routing_threshold_sweep"),
    ("jailbreakbench_completion_scorer_smoke", "jailbreakbench_completion_scorer_smoke"),
    ("harm_adv_completion_scorer", "harm_adv_completion_scorer_smoke"),
    ("harmbench_official_completion_manifest", "harmbench_official_completion_manifest"),
    ("harmbench_step3_importer_preflight", "harmbench_step3_importer_preflight"),
    ("harmbench_step3_result_guard", "harmbench_step3_result_guard"),
    ("harmbench_official_step3_result", "harmbench_official_step3_result_summary"),
    ("harmbench_official_method_comparison", "harmbench_official_method_comparison"),
    ("advbench_official_method_comparison", "advbench_official_method_comparison"),
    ("harmbench_local_official", "harmbench_local_official_reproduction"),
    ("official_judge_tradeoff", "official_judge_tradeoff"),
    ("official_judge_routing_ablation", "official_judge_routing_ablation"),
    ("agentdojo_injecagent_official_task_graph", "agent_task_graph_mapping"),
    ("agentdojo_injecagent_task_graph_replay", "agent_task_graph_replay_alignment"),
    ("agentdojo_injecagent_task_state", "agent_task_state_harness"),
    ("official_evaluator_reproducibility_ledger", "official_evaluator_reproducibility_ledger"),
    ("official_evaluator_gap_closure_plan", "official_evaluator_gap_closure_plan"),
    ("strongreject_official_compatible_scorer", "strongreject_official_compatible_scorer"),
    ("strongreject_guardx_official_adapter", "strongreject_guardx_official_adapter"),
    ("strongreject_official_autograder_preflight", "strongreject_official_autograder_preflight"),
    ("upstream_evaluator_smoke_readiness", "upstream_evaluator_smoke_readiness"),
    ("upstream_evaluator_runnable_checklist", "upstream_evaluator_runnable_checklist"),
    ("official_evaluator_parity", "official_evaluator_parity"),
    ("agent_vlm_realism", "agent_vlm_realism"),
    ("unified_defense_ablation", "unified_defense_ablation"),
    ("judge_aware_policy_profile", "judge_aware_policy_profile"),
    ("real_executor", "real_executor_replay"),
    ("judge_provider_healthcheck", "judge_provider_healthcheck"),
    ("official_leaderboard_readiness", "official_leaderboard_readiness"),
    ("vlm_provider_probe", "vlm_provider_probe"),
    ("agent_end_to_end", "agent_end_to_end_replay"),
    ("defense_action_ablation", "defense_action_ablation"),
    ("local_lora_semantic_classifier", "local_lora_semantic_eval"),
    ("demo_storyline", "demo_storyline_replay"),
    ("external_benchmark_evidence", "external_benchmark_evidence"),
    ("semantic_method", "semantic_method_matrix"),
    ("layered_baseline", "layered_baseline_comparison"),
    ("adaptive_external", "adaptive_external_baselines"),
    ("adaptive_baseline", "adaptive_baseline_comparison"),
    ("dry_run", "real_model_matrix_plan"),
    ("embedding_ablation", "embedding_ablation"),
    ("glue_decoder_baseline", "glue_decoder_baseline"),
    ("decoder_probe", "decoder_probe"),
    ("competition_readiness", "competition_readiness"),
    ("competition_gap_radar", "competition_gap_radar"),
    ("model_feedback_loop", "model_feedback_loop"),
    ("target_integration_replay", "target_integration_replay"),
    ("live_target_preflight", "live_target_preflight"),
    ("live_target_readiness", "live_target_readiness"),
    ("live_target_rehearsal", "live_target_rehearsal"),
    ("public_benchmark", "public_benchmark_gate"),
    ("skipped", "run_status"),
    ("regression_gate", "regression_gate"),
    ("reliability_gate", "reliability_gate"),
    ("contest_attack", "contest_attack_matrix"),
    ("stability", "stability"),
    ("summary", "summary"),
]


def load_json_metadata(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"parse_error": str(exc)}

    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    models = data.get("models") or summary.get("models")
    if isinstance(models, dict):
        models = sorted(models)
    missing_env = data.get("missing_env") if isinstance(data.get("missing_env"), dict) else {}
    missing_env_count = sum(len(values or []) for values in missing_env.values())
    recommended_models = data.get("recommended_models") or summary.get("recommended_models") or summary.get("ready_models")
    if not recommended_models and summary.get("recommended_model"):
        recommended_models = [summary["recommended_model"]]
    decoder_metrics = data.get("reconstruction_metrics") if isinstance(data.get("reconstruction_metrics"), list) else []
    best_decoder_metric = max(decoder_metrics, key=lambda item: float(item.get("token_f1") or 0.0), default={})
    baselines = data.get("baselines") if isinstance(data.get("baselines"), dict) else {}
    baseline_summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    guardx_full = baseline_summary.get("guardx_full", {}) if isinstance(baseline_summary.get("guardx_full"), dict) else {}
    ok_baselines = [name for name, item in baselines.items() if isinstance(item, dict) and item.get("status") == "ok"]
    failed_baselines = [name for name, item in baselines.items() if isinstance(item, dict) and item.get("status") not in {"ok", None}]
    overall = data.get("overall") if isinstance(data.get("overall"), dict) else {}
    local_semantic = overall.get("local_trained_classifier", {}) if isinstance(overall.get("local_trained_classifier"), dict) else {}
    combined_semantic = overall.get("combined_semantic_guard", {}) if isinstance(overall.get("combined_semantic_guard"), dict) else {}
    hf_semantic = overall.get("hf_transformer_classifier", {}) if isinstance(overall.get("hf_transformer_classifier"), dict) else {}
    method_names = data.get("methods") if isinstance(data.get("methods"), list) else []
    semantic_methods = [str(item) for item in method_names]
    best_semantic_method = ""
    if overall:
        best_semantic_method = max(
            overall.items(),
            key=lambda item: (float(item[1].get("attack_catch_rate", 0.0) or 0.0), -float(item[1].get("false_positive_rate", 0.0) or 0.0))
            if isinstance(item[1], dict)
            else (0.0, 0.0),
        )[0]
    evidence_chains = data.get("evidence_chains") if isinstance(data.get("evidence_chains"), list) else []
    chain_sample = evidence_chains[0] if evidence_chains and isinstance(evidence_chains[0], dict) else {}
    chain_finding = chain_sample.get("risk_finding") if isinstance(chain_sample.get("risk_finding"), dict) else {}
    chain_decision = chain_sample.get("policy_decision") if isinstance(chain_sample.get("policy_decision"), dict) else {}
    chain_replay = chain_sample.get("replay_evidence") if isinstance(chain_sample.get("replay_evidence"), dict) else {}
    judge_preflight = data.get("judge_preflight") if isinstance(data.get("judge_preflight"), dict) else {}
    by_suite = data.get("by_suite") if isinstance(data.get("by_suite"), dict) else {}
    lora_heldout = by_suite.get("guardx_adaptive_heldout_v2", {}) if isinstance(by_suite.get("guardx_adaptive_heldout_v2"), dict) else {}
    lora_official = by_suite.get("guardx_official_semantic_subset_v1", {}) if isinstance(by_suite.get("guardx_official_semantic_subset_v1"), dict) else {}
    lora_fpr = by_suite.get("guardx_false_positive_recovery_probe", {}) if isinstance(by_suite.get("guardx_false_positive_recovery_probe"), dict) else {}
    defense_overall = data.get("overall") if isinstance(data.get("overall"), dict) else {}
    defense_detect = defense_overall.get("detect_only_alert", {}) if isinstance(defense_overall.get("detect_only_alert"), dict) else {}
    defense_policy = defense_overall.get("policy_gate", {}) if isinstance(defense_overall.get("policy_gate"), dict) else {}
    defense_orch = defense_overall.get("defense_action_orchestrated", {}) if isinstance(defense_overall.get("defense_action_orchestrated"), dict) else {}
    stages = data.get("stages") if isinstance(data.get("stages"), list) else []
    provider_results = data.get("results") if isinstance(data.get("results"), list) else []
    provider_ok = [str(item.get("profile")) for item in provider_results if isinstance(item, dict) and item.get("ok")]
    provider_failed = [
        str(item.get("profile"))
        for item in provider_results
        if isinstance(item, dict) and item.get("ok") is False and item.get("status") != "skipped_missing_api_key"
    ]
    provider_skipped = [
        str(item.get("profile"))
        for item in provider_results
        if isinstance(item, dict) and item.get("status") == "skipped_missing_api_key"
    ]
    readiness_checks = data.get("checks") if isinstance(data.get("checks"), list) else []
    readiness_statuses = {
        str(item.get("item")): item.get("status")
        for item in readiness_checks
        if isinstance(item, dict) and item.get("item")
    }
    real_executor_cases = data.get("cases") if isinstance(data.get("cases"), list) else []
    real_executor_summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    judge_profile_routes = data.get("routes") if isinstance(data.get("routes"), dict) else data.get("route_policy") if isinstance(data.get("route_policy"), dict) else {}
    unified_profiles = data.get("profiles") if isinstance(data.get("profiles"), list) else []
    unified_best_low_block = data.get("best_low_benign_block_profile") if isinstance(data.get("best_low_benign_block_profile"), dict) else {}
    agent_vlm_summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    xstest_summary = data.get("summary") if isinstance(data.get("summary"), dict) and data.get("schema_version") == "guardx-xstest-local-official-reproduction-v1" else {}
    harmbench_summary = data.get("summary") if isinstance(data.get("summary"), dict) and data.get("schema_version") == "guardx-harmbench-local-official-reproduction-v1" else {}
    advbench_summary = data.get("summary") if isinstance(data.get("summary"), dict) and data.get("schema_version") == "guardx-advbench-local-official-reproduction-v1" else {}
    jailbreakbench_summary = (
        data.get("summary")
        if isinstance(data.get("summary"), dict)
        and data.get("schema_version") == "guardx-jailbreakbench-local-official-reproduction-v1"
        else {}
    )
    jailbreakbench_manifest = (
        data.get("dataset_manifest")
        if isinstance(data.get("dataset_manifest"), dict)
        and data.get("schema_version") == "guardx-jailbreakbench-local-official-reproduction-v1"
        else {}
    )
    harmbench_methods = data.get("methods") if isinstance(data.get("methods"), list) and data.get("schema_version") == "guardx-harmbench-official-method-comparison-v1" else []
    harmbench_best = data.get("best_method") if isinstance(data.get("best_method"), dict) and data.get("schema_version") == "guardx-harmbench-official-method-comparison-v1" else {}
    advbench_methods = data.get("methods") if isinstance(data.get("methods"), list) and data.get("schema_version") == "guardx-advbench-official-method-comparison-v1" else []
    advbench_best_recall = (
        data.get("best_recall_method")
        if isinstance(data.get("best_recall_method"), dict)
        and data.get("schema_version") == "guardx-advbench-official-method-comparison-v1"
        else {}
    )
    advbench_best_low_review = (
        data.get("best_low_review_method")
        if isinstance(data.get("best_low_review_method"), dict)
        and data.get("schema_version") == "guardx-advbench-official-method-comparison-v1"
        else {}
    )
    jailbreakbench_methods = (
        data.get("methods")
        if isinstance(data.get("methods"), list)
        and data.get("schema_version") == "guardx-jailbreakbench-official-method-comparison-v1"
        else []
    )
    jailbreakbench_best_recall = (
        data.get("best_recall_method")
        if isinstance(data.get("best_recall_method"), dict)
        and data.get("schema_version") == "guardx-jailbreakbench-official-method-comparison-v1"
        else {}
    )
    jailbreakbench_best_low_fpr = (
        data.get("best_low_fpr_method")
        if isinstance(data.get("best_low_fpr_method"), dict)
        and data.get("schema_version") == "guardx-jailbreakbench-official-method-comparison-v1"
        else {}
    )
    jailbreakbench_deepseek = next(
        (row for row in jailbreakbench_methods if isinstance(row, dict) and row.get("method") == "deepseek_judge"),
        {},
    )
    jailbreakbench_qwen = next(
        (row for row in jailbreakbench_methods if isinstance(row, dict) and row.get("method") == "qwen_judge"),
        {},
    )
    jailbreakbench_runtime = next(
        (row for row in jailbreakbench_methods if isinstance(row, dict) and row.get("method") == "guardx_runtime_only"),
        {},
    )
    harmbench_qwen = next(
        (row for row in harmbench_methods if isinstance(row, dict) and row.get("method") == "qwen_judge"),
        {},
    )
    harmbench_runtime = next(
        (row for row in harmbench_methods if isinstance(row, dict) and row.get("method") == "guardx_runtime_only"),
        {},
    )
    judge_tradeoff_methods = data.get("methods") if isinstance(data.get("methods"), list) and data.get("schema_version") == "guardx-official-judge-tradeoff-v1" else []
    judge_tradeoff_balanced = data.get("balanced_judge") if isinstance(data.get("balanced_judge"), dict) else {}
    judge_tradeoff_low_fpr = data.get("low_fpr_judge") if isinstance(data.get("low_fpr_judge"), dict) else {}
    judge_tradeoff_high_recall = data.get("high_recall_judge") if isinstance(data.get("high_recall_judge"), dict) else {}
    judge_tradeoff_deepseek = next(
        (row for row in judge_tradeoff_methods if isinstance(row, dict) and row.get("method") == "deepseek_judge"),
        {},
    )
    judge_tradeoff_qwen = next(
        (row for row in judge_tradeoff_methods if isinstance(row, dict) and row.get("method") == "qwen_judge"),
        {},
    )
    judge_routing_providers = data.get("providers") if isinstance(data.get("providers"), list) and data.get("schema_version") == "guardx-official-judge-routing-ablation-v1" else []
    judge_routing_deepseek = next(
        (row for row in judge_routing_providers if isinstance(row, dict) and row.get("provider") == "deepseek"),
        {},
    )
    judge_routing_qwen = next(
        (row for row in judge_routing_providers if isinstance(row, dict) and row.get("provider") == "qwen"),
        {},
    )
    judge_routing_deepseek_routed_xstest = (
        judge_routing_deepseek.get("routed", {}).get("xstest", {})
        if isinstance(judge_routing_deepseek.get("routed"), dict)
        else {}
    )
    judge_routing_deepseek_direct_xstest = (
        judge_routing_deepseek.get("direct", {}).get("xstest", {})
        if isinstance(judge_routing_deepseek.get("direct"), dict)
        else {}
    )
    judge_routing_qwen_routed_xstest = (
        judge_routing_qwen.get("routed", {}).get("xstest", {})
        if isinstance(judge_routing_qwen.get("routed"), dict)
        else {}
    )
    judge_routing_qwen_direct_xstest = (
        judge_routing_qwen.get("direct", {}).get("xstest", {})
        if isinstance(judge_routing_qwen.get("direct"), dict)
        else {}
    )
    judge_routing_deepseek_routed_harm = (
        judge_routing_deepseek.get("routed", {}).get("harmbench", {})
        if isinstance(judge_routing_deepseek.get("routed"), dict)
        else {}
    )
    judge_routing_qwen_routed_harm = (
        judge_routing_qwen.get("routed", {}).get("harmbench", {})
        if isinstance(judge_routing_qwen.get("routed"), dict)
        else {}
    )
    jbb_routing_providers = (
        data.get("providers")
        if isinstance(data.get("providers"), list)
        and data.get("schema_version") == "guardx-jailbreakbench-judge-routing-ablation-v1"
        else []
    )
    jbb_routing_deepseek = next(
        (row for row in jbb_routing_providers if isinstance(row, dict) and row.get("provider") == "deepseek"),
        {},
    )
    jbb_routing_qwen = next(
        (row for row in jbb_routing_providers if isinstance(row, dict) and row.get("provider") == "qwen"),
        {},
    )
    jbb_routing_deepseek_direct = (
        jbb_routing_deepseek.get("direct", {}).get("jailbreakbench", {})
        if isinstance(jbb_routing_deepseek.get("direct"), dict)
        else {}
    )
    jbb_routing_deepseek_routed = (
        jbb_routing_deepseek.get("routed", {}).get("jailbreakbench", {})
        if isinstance(jbb_routing_deepseek.get("routed"), dict)
        else {}
    )
    jbb_routing_qwen_direct = (
        jbb_routing_qwen.get("direct", {}).get("jailbreakbench", {})
        if isinstance(jbb_routing_qwen.get("direct"), dict)
        else {}
    )
    jbb_routing_qwen_routed = (
        jbb_routing_qwen.get("routed", {}).get("jailbreakbench", {})
        if isinstance(jbb_routing_qwen.get("routed"), dict)
        else {}
    )
    jbb_threshold_low = (
        data.get("recommended_low_review_profile")
        if isinstance(data.get("recommended_low_review_profile"), dict)
        and data.get("schema_version") == "guardx-jailbreakbench-judge-routing-threshold-sweep-v1"
        else {}
    )
    jbb_threshold_high = (
        data.get("recommended_high_recall_profile")
        if isinstance(data.get("recommended_high_recall_profile"), dict)
        and data.get("schema_version") == "guardx-jailbreakbench-judge-routing-threshold-sweep-v1"
        else {}
    )
    jbb_threshold_rows = (
        data.get("rows")
        if isinstance(data.get("rows"), list)
        and data.get("schema_version") == "guardx-jailbreakbench-judge-routing-threshold-sweep-v1"
        else []
    )
    jbb_completion_summary = (
        data.get("summary")
        if isinstance(data.get("summary"), dict)
        and data.get("schema_version") == "guardx-jailbreakbench-completion-scorer-smoke-v1"
        else {}
    )
    harm_adv_completion_summary = (
        data.get("summary")
        if isinstance(data.get("summary"), dict)
        and data.get("schema_version") == "guardx-harm-adv-completion-scorer-smoke-v1"
        else {}
    )
    harm_adv_completion_by_benchmark = (
        harm_adv_completion_summary.get("by_benchmark")
        if isinstance(harm_adv_completion_summary.get("by_benchmark"), dict)
        else {}
    )
    harmbench_step3_preflight = (
        data.get("preflight")
        if isinstance(data.get("preflight"), dict)
        and data.get("schema_version") == "guardx-harmbench-official-completion-manifest-v1"
        else {}
    )
    harmbench_step3_modules = (
        harmbench_step3_preflight.get("python_modules")
        if isinstance(harmbench_step3_preflight.get("python_modules"), dict)
        else {}
    )
    harmbench_step3_importer_checks = (
        data.get("checks")
        if isinstance(data.get("checks"), dict)
        and data.get("schema_version") == "guardx-harmbench-step3-importer-preflight-v1"
        else {}
    )
    harmbench_step3_result_summary = (
        data.get("summary")
        if isinstance(data.get("summary"), dict)
        and data.get("schema_version") == "guardx-harmbench-official-step3-result-summary-v1"
        else {}
    )
    harmbench_step3_result_guard_checks = (
        data.get("checks")
        if isinstance(data.get("checks"), dict)
        and data.get("schema_version") == "guardx-harmbench-step3-result-guard-v1"
        else {}
    )
    vlm_multi_image_summary = data.get("summary") if isinstance(data.get("summary"), dict) and data.get("schema_version") == "guardx-vlm-multi-image-provider-benchmark-v1" else {}
    agent_task_graph_summary = data.get("summary") if isinstance(data.get("summary"), dict) and data.get("schema_version") == "guardx-agentdojo-injecagent-official-task-graph-mapping-v1" else {}
    agent_task_graph_alignment_summary = data.get("summary") if isinstance(data.get("summary"), dict) and data.get("schema_version") == "guardx-agentdojo-injecagent-task-graph-replay-alignment-v1" else {}
    official_parity_rows = data.get("rows") if isinstance(data.get("rows"), list) and data.get("schema_version") == "guardx-official-evaluator-parity-matrix-v1" else []
    official_parity_ready = [
        row
        for row in official_parity_rows
        if isinstance(row, dict) and row.get("ready_for_local_official_reproduction")
    ]
    official_parity_local_evidence = [
        row
        for row in official_parity_rows
        if isinstance(row, dict) and ((row.get("local_official_reproduction") or {}).get("exists") is True)
    ]
    official_parity_xstest = next(
        (row for row in official_parity_rows if isinstance(row, dict) and row.get("benchmark") == "XSTest"),
        {},
    )
    official_parity_missing_expected_files = [
        str(missing)
        for row in official_parity_rows
        if isinstance(row, dict)
        for missing in ((row.get("repo_check") or {}).get("missing_expected_files") or [])
    ]
    official_ledger_rows = data.get("rows") if isinstance(data.get("rows"), list) and data.get("schema_version") == "guardx-official-evaluator-reproducibility-ledger-v1" else []
    official_ledger_summaries = (
        data.get("benchmark_summaries")
        if isinstance(data.get("benchmark_summaries"), dict)
        and data.get("schema_version") == "guardx-official-evaluator-reproducibility-ledger-v1"
        else {}
    )
    official_ledger_xstest = next(
        (row for row in official_ledger_rows if isinstance(row, dict) and row.get("benchmark") == "XSTest"),
        {},
    )
    official_ledger_harmbench = next(
        (row for row in official_ledger_rows if isinstance(row, dict) and row.get("benchmark") == "HarmBench"),
        {},
    )
    official_ledger_jailbreakbench = next(
        (row for row in official_ledger_rows if isinstance(row, dict) and row.get("benchmark") == "JailbreakBench"),
        {},
    )
    official_ledger_agent = next(
        (row for row in official_ledger_rows if isinstance(row, dict) and row.get("benchmark") == "AgentDojo/InjecAgent"),
        {},
    )
    official_ledger_xstest_metrics = official_ledger_xstest.get("metrics") if isinstance(official_ledger_xstest.get("metrics"), dict) else {}
    official_ledger_harmbench_metrics = official_ledger_harmbench.get("metrics") if isinstance(official_ledger_harmbench.get("metrics"), dict) else {}
    official_ledger_jailbreakbench_metrics = (
        official_ledger_jailbreakbench.get("metrics")
        if isinstance(official_ledger_jailbreakbench.get("metrics"), dict)
        else {}
    )
    official_ledger_agent_metrics = official_ledger_agent.get("metrics") if isinstance(official_ledger_agent.get("metrics"), dict) else {}
    upstream_check_rows = data.get("rows") if isinstance(data.get("rows"), list) and data.get("schema_version") == "guardx-upstream-evaluator-runnable-checklist-v1" else []
    upstream_check_status_counts = data.get("status_counts") if isinstance(data.get("status_counts"), dict) and data.get("schema_version") == "guardx-upstream-evaluator-runnable-checklist-v1" else {}
    upstream_check_ready = [
        row
        for row in upstream_check_rows
        if isinstance(row, dict) and row.get("status") == "upstream_evaluator_ready"
    ]
    upstream_check_data_only = [
        row
        for row in upstream_check_rows
        if isinstance(row, dict) and row.get("status") == "local_official_data_only"
    ]
    upstream_check_repo_like = [
        row
        for row in upstream_check_rows
        if isinstance(row, dict) and row.get("status") == "local_repo_like_files_present_env_not_set"
    ]
    upstream_check_proxy_missing = [
        row
        for row in upstream_check_rows
        if isinstance(row, dict) and row.get("status") == "proxy_or_missing_local_assets"
    ]
    upstream_smoke_rows = data.get("rows") if isinstance(data.get("rows"), list) and data.get("schema_version") == "guardx-upstream-evaluator-smoke-readiness-v1" else []
    upstream_smoke_ready = [
        row
        for row in upstream_smoke_rows
        if isinstance(row, dict) and row.get("smoke_ready")
    ]
    upstream_smoke_compile_ok = [
        row
        for row in upstream_smoke_rows
        if isinstance(row, dict) and row.get("compile_ready")
    ]
    upstream_smoke_data_ready = [
        row
        for row in upstream_smoke_rows
        if isinstance(row, dict) and row.get("data_ready")
    ]
    strongreject_files = data.get("files") if isinstance(data.get("files"), dict) and data.get("schema_version") == "guardx-strongreject-official-autograder-preflight-v1" else {}
    strongreject_full = strongreject_files.get("full_dataset") if isinstance(strongreject_files.get("full_dataset"), dict) else {}
    strongreject_small = strongreject_files.get("small_dataset") if isinstance(strongreject_files.get("small_dataset"), dict) else {}
    strongreject_refusal = data.get("parser_synthetic_refusal") if isinstance(data.get("parser_synthetic_refusal"), dict) else {}
    strongreject_non_refusal = data.get("parser_synthetic_non_refusal") if isinstance(data.get("parser_synthetic_non_refusal"), dict) else {}
    strongreject_adapter_summary = (
        data.get("summary")
        if isinstance(data.get("summary"), dict)
        and data.get("schema_version") == "guardx-strongreject-guardx-official-adapter-v1"
        else {}
    )
    strongreject_scorer_summary = (
        data.get("summary")
        if isinstance(data.get("summary"), dict)
        and data.get("schema_version") == "guardx-strongreject-official-compatible-scorer-v1"
        else {}
    )
    benign_recovery_train = data.get("train") if isinstance(data.get("train"), dict) else {}
    benign_recovery_eval = data.get("eval") if isinstance(data.get("eval"), dict) else {}
    same_batch_methods = data.get("methods") if isinstance(data.get("methods"), dict) else {}
    if not same_batch_methods and isinstance(data.get("by_method"), dict):
        same_batch_methods = data.get("by_method") or {}
    same_batch_complete_methods = data.get("complete_methods") if isinstance(data.get("complete_methods"), list) else []
    same_batch_partial_methods = data.get("partial_methods") if isinstance(data.get("partial_methods"), dict) else {}
    if same_batch_methods and not same_batch_complete_methods and not same_batch_partial_methods:
        same_batch_max_cases = max((int(item.get("cases", 0) or 0) for item in same_batch_methods.values() if isinstance(item, dict)), default=0)
        same_batch_complete_methods = [
            method
            for method, item in same_batch_methods.items()
            if isinstance(item, dict) and int(item.get("cases", 0) or 0) == same_batch_max_cases
        ]
        same_batch_partial_methods = {
            method: item.get("cases")
            for method, item in same_batch_methods.items()
            if isinstance(item, dict) and int(item.get("cases", 0) or 0) != same_batch_max_cases
        }
    same_batch_default_profile = str(data.get("default_profile") or "")
    same_batch_full = same_batch_methods.get(same_batch_default_profile, {}) if isinstance(same_batch_methods.get(same_batch_default_profile), dict) else {}
    if not same_batch_full:
        for method in (
            "guardx_full_routed",
            "guardx_layer_aware_7b_lora_v2_soft_boundary_1079",
            "guardx_layer_aware_7b_lora_v2_soft_boundary_254",
            "guardx_layer_aware_judge_v3_routed",
            "guardx_layer_aware_judge_v3_agentdojo_254",
            "guardx_runtime_only",
        ):
            candidate = same_batch_methods.get(method)
            if isinstance(candidate, dict):
                same_batch_full = candidate
                same_batch_default_profile = method
                break
    same_batch_judge = same_batch_methods.get("judge_only", {}) if isinstance(same_batch_methods.get("judge_only"), dict) else {}
    if not same_batch_judge:
        for method in ("deepseek_judge", "qwen_judge", "zhipu_judge", "kimi_judge"):
            candidate = same_batch_methods.get(method)
            if isinstance(candidate, dict):
                same_batch_judge = candidate
                break
    same_batch_lora = same_batch_methods.get("lora_only", {}) if isinstance(same_batch_methods.get("lora_only"), dict) else {}
    if not same_batch_lora:
        for method in (
            "local_lora_deepseek_qwen7b_targeted_v4_qlora300_forced_choice_tuned045",
            "local_lora_deepseek_qwen7b_targeted_v4_qlora300_forced_choice_tuned037",
            "local_lora_rag_tool_agent_targeted_v4_300_forced_choice_tuned061",
            "local_lora_rag_tool_agent_300_forced_choice_calibrated",
        ):
            candidate = same_batch_methods.get(method)
            if isinstance(candidate, dict):
                same_batch_lora = candidate
                break
    same_batch_runtime = same_batch_methods.get("runtime_only", {}) if isinstance(same_batch_methods.get("runtime_only"), dict) else {}
    if not same_batch_runtime:
        candidate = same_batch_methods.get("guardx_runtime_only")
        same_batch_runtime = candidate if isinstance(candidate, dict) else {}
    lora_routing_results = data.get("results") if isinstance(data.get("results"), dict) else {}
    lora_routing_standalone = lora_routing_results.get("standalone_specialist", {}) if isinstance(lora_routing_results.get("standalone_specialist"), dict) else {}
    lora_routing_routed = lora_routing_results.get("routed_policy", {}) if isinstance(lora_routing_results.get("routed_policy"), dict) else {}
    lora_routing_layer = lora_routing_results.get("layer_aware_routed_policy", {}) if isinstance(lora_routing_results.get("layer_aware_routed_policy"), dict) else {}
    lora_routing_delta = data.get("delta") if isinstance(data.get("delta"), dict) else {}
    final_gate_checks = (
        data.get("checks")
        if isinstance(data.get("checks"), list)
        and data.get("schema_version") == "guardx-final-submission-gate-v1"
        else []
    )
    final_gate_failed = [
        row
        for row in final_gate_checks
        if isinstance(row, dict) and row.get("status") != "pass"
    ]
    portal_rehearsal = data if data.get("schema_version") == "guardx-portal-rehearsal-v1" else {}
    portal_rehearsal_health = (
        portal_rehearsal.get("competition_demo_health")
        if isinstance(portal_rehearsal.get("competition_demo_health"), dict)
        else {}
    )
    portal_rehearsal_gate = (
        portal_rehearsal.get("artifact_endpoint_probe")
        if isinstance(portal_rehearsal.get("artifact_endpoint_probe"), dict)
        else {}
    )
    portal_rehearsal_cards = (
        portal_rehearsal.get("rendered_cards")
        if isinstance(portal_rehearsal.get("rendered_cards"), dict)
        else {}
    )
    portal_rehearsal_screenshot = (
        portal_rehearsal.get("local_screenshot")
        if isinstance(portal_rehearsal.get("local_screenshot"), dict)
        else {}
    )
    presentation_freshness = (
        data if data.get("schema_version") == "guardx-presentation-freshness-check-v1" else {}
    )
    presentation_decks = (
        presentation_freshness.get("decks")
        if isinstance(presentation_freshness.get("decks"), list)
        else []
    )
    presentation_stale_count = sum(
        len(row.get("stale_hits") or []) for row in presentation_decks if isinstance(row, dict)
    )
    presentation_missing_count = len(presentation_freshness.get("global_missing_terms") or []) + sum(
        len(row.get("missing_required_terms") or []) for row in presentation_decks if isinstance(row, dict)
    )
    presentation_secret_like_count = sum(
        len(row.get("secret_like_hits") or []) for row in presentation_decks if isinstance(row, dict)
    )
    demo_flow_summary = data if data.get("schema_version") == "guardx-demo-flow-summary-v1" else {}
    final_demo_stories = (
        demo_flow_summary.get("stories")
        if isinstance(demo_flow_summary.get("stories"), list)
        else []
    )
    competition_submission_audit = (
        data if data.get("schema_version") == "guardx-competition-submission-readiness-audit-v1" else {}
    )
    claim_defense_matrix = data if data.get("schema_version") == "guardx-claim-defense-matrix-v1" else {}
    claim_defense_items = (
        claim_defense_matrix.get("items") if isinstance(claim_defense_matrix.get("items"), list) else []
    )
    final_rehearsal_runbook = data if data.get("schema_version") == "guardx-final-rehearsal-runbook-v1" else {}
    final_rehearsal_commands = (
        final_rehearsal_runbook.get("preflight_commands")
        if isinstance(final_rehearsal_runbook.get("preflight_commands"), list)
        else []
    )
    final_rehearsal_flow = (
        final_rehearsal_runbook.get("demo_flow")
        if isinstance(final_rehearsal_runbook.get("demo_flow"), list)
        else []
    )
    final_rehearsal_qna = (
        final_rehearsal_runbook.get("qna_drill")
        if isinstance(final_rehearsal_runbook.get("qna_drill"), list)
        else []
    )
    final_rehearsal_pitch = (
        final_rehearsal_runbook.get("pitch_script")
        if isinstance(final_rehearsal_runbook.get("pitch_script"), list)
        else []
    )
    official_submission_handoff = (
        data if data.get("schema_version") == "guardx-official-submission-handoff-checklist-v1" else {}
    )
    official_submission_manual_items = (
        official_submission_handoff.get("manual_items")
        if isinstance(official_submission_handoff.get("manual_items"), list)
        else []
    )
    official_submission_sources = (
        official_submission_handoff.get("public_sources")
        if isinstance(official_submission_handoff.get("public_sources"), list)
        else []
    )
    demo_recording_plan = data if data.get("schema_version") == "guardx-demo-recording-plan-v1" else {}
    final_demo_video_shots = (
        demo_recording_plan.get("shotlist")
        if isinstance(demo_recording_plan.get("shotlist"), list)
        else []
    )
    final_demo_video_recording_checks = (
        demo_recording_plan.get("recording_checklist")
        if isinstance(demo_recording_plan.get("recording_checklist"), list)
        else []
    )
    final_packet_cover = data if data.get("schema_version") == "guardx-final-submission-packet-cover-v1" else {}
    final_packet_upload_items = (
        final_packet_cover.get("upload_items") if isinstance(final_packet_cover.get("upload_items"), list) else []
    )
    final_packet_manual_items = (
        final_packet_cover.get("manual_after_upload") if isinstance(final_packet_cover.get("manual_after_upload"), list) else []
    )
    judge_rubric_scorecard = data if data.get("schema_version") == "guardx-judge-rubric-scorecard-v1" else {}
    judge_rubric_dimensions = (
        judge_rubric_scorecard.get("dimensions") if isinstance(judge_rubric_scorecard.get("dimensions"), list) else []
    )
    judge_rubric_non_claims = (
        judge_rubric_scorecard.get("non_claims") if isinstance(judge_rubric_scorecard.get("non_claims"), list) else []
    )
    benchmark_traceability = data if data.get("schema_version") == "guardx-benchmark-traceability-matrix-v1" else {}
    final_live_demo_scorecard = data if data.get("schema_version") == "guardx-final-live-demo-rehearsal-scorecard-v1" else {}
    submission_package = data if data.get("schema_version") == "guardx-submission-package-manifest-v1" else {}
    reviewer_reproduction = data if data.get("schema_version") == "guardx-reviewer-reproduction-commands-v1" else {}
    public_archive_review_scan = data if data.get("schema_version") == "guardx-public-archive-review-scan-v1" else {}
    public_archive_reproduction_smoke = (
        data if data.get("schema_version") == "guardx-public-archive-reproduction-smoke-v1" else {}
    )
    return {
        "schema_version": data.get("schema_version"),
        "run_id": data.get("run_id") or summary.get("run_id"),
        "dry_run": data.get("dry_run"),
        "skipped": data.get("skipped"),
        "suite_id": data.get("suite_id") or summary.get("suite_id"),
        "policy_profile": data.get("policy_profile") or data.get("profile") or summary.get("policy_profile"),
        "models": models or data.get("configured_models") or [],
        "requested_models": data.get("requested_models") or [],
        "requested_profiles": data.get("requested_profiles") or [],
        "required_profiles": data.get("required_profiles") or [],
        "passed": data.get("passed") if data.get("passed") is not None else data.get("ready"),
        "blocker_count": data.get("blocker_count"), "external_blocker_count": data.get("external_blocker_count"), "required_failure_count": data.get("required_failure_count"), "validated_case_count": data.get("validated_case_count"), "score": data.get("score"),
        "stable_models": data.get("stable_models") or summary.get("stable_models") or [],
        "recommended_models": recommended_models or [],
        "promoted_models": data.get("promoted_models") or summary.get("promoted_models") or [],
        "demoted_models": data.get("demoted_models") or summary.get("demoted_models") or [],
        "thresholds": data.get("thresholds") or summary.get("thresholds") or {},
        "profile_count": len(data.get("profiles") or []),
        "skipped_profile_count": data.get("skipped_profile_count", 0),
        "failed_profile_count": data.get("failed_profile_count", 0),
        "required_profile_failure_count": data.get("required_profile_failure_count", 0),
        "eval_only": data.get("eval_only"), "production_routing": data.get("production_routing"),
        "glue_task": data.get("glue_task"), "train_size": data.get("train_size"), "eval_size": data.get("eval_size"),
        "variants": data.get("variants") or [], "attacks": data.get("attacks") or [],
        "max_risk_score": data.get("max_risk_score"), "max_token_f1": data.get("max_token_f1"),
        "contains_raw_text": data.get("contains_raw_text"), "raw_text_policy": data.get("raw_text_policy"), "blocking_reasons": data.get("blocking_reasons") or [],
        "best_decoder_attack": best_decoder_metric.get("attack"), "best_decoder_variant": best_decoder_metric.get("embedding_variant"),
        "best_decoder_epochs": best_decoder_metric.get("decoder_epochs"), "best_decoder_vocab_size": best_decoder_metric.get("decoder_vocab_size"),
        "best_decoder_token_recall": best_decoder_metric.get("token_recall"), "best_decoder_label_match_rate": best_decoder_metric.get("label_match_rate"),
        "missing_env_models": sorted(missing_env), "missing_env_count": missing_env_count,
        "excluded_count": len(data.get("excluded_models", []) or summary.get("excluded_models", []) or []),
        "baseline_count": len(baselines) or len(baseline_summary),
        "ok_baselines": sorted(ok_baselines),
        "failed_baselines": sorted(failed_baselines),
        "guardx_full_accuracy": guardx_full.get("accuracy"),
        "guardx_full_attack_catch_rate": guardx_full.get("attack_catch_rate"),
        "guardx_full_false_positive_rate": guardx_full.get("false_positive_rate"),
        "semantic_methods": semantic_methods,
        "best_semantic_method": best_semantic_method,
        "local_semantic_attack_catch_rate": local_semantic.get("attack_catch_rate"),
        "local_semantic_false_positive_rate": local_semantic.get("false_positive_rate"),
        "combined_semantic_attack_catch_rate": combined_semantic.get("attack_catch_rate"),
        "combined_semantic_false_positive_rate": combined_semantic.get("false_positive_rate"),
        "hf_semantic_attack_catch_rate": hf_semantic.get("attack_catch_rate"),
        "hf_semantic_false_positive_rate": hf_semantic.get("false_positive_rate"),
        "semantic_chain_case_id": chain_sample.get("case_id"),
        "semantic_chain_methods": chain_sample.get("detection_methods") or [],
        "semantic_chain_route": chain_decision.get("route"),
        "semantic_chain_policy_action": chain_decision.get("action"),
        "semantic_chain_policy_score": chain_decision.get("risk_score"),
        "semantic_chain_risk_type": chain_finding.get("risk_type"),
        "semantic_chain_risk_score": chain_finding.get("risk_score"),
        "semantic_chain_risk_severity": chain_finding.get("severity"),
        "semantic_chain_defense_actions": [
            str(item.get("defense_id"))
            for item in (chain_sample.get("defense_actions") or [])
            if isinstance(item, dict) and item.get("defense_id")
        ],
        "semantic_chain_replay_ref": chain_replay.get("trace_ref"),
        "semantic_judge_ready": judge_preflight.get("ready"),
        "semantic_judge_provider": judge_preflight.get("provider"),
        "semantic_judge_missing_env": judge_preflight.get("missing_env") or [],
        "lora_device": data.get("device"),
        "lora_adapter_dir": data.get("adapter_dir"),
        "lora_heldout_attack_catch_rate": lora_heldout.get("attack_catch_rate"),
        "lora_heldout_false_positive_rate": lora_heldout.get("false_positive_rate"),
        "lora_official_attack_catch_rate": lora_official.get("attack_catch_rate"),
        "lora_official_false_positive_rate": lora_official.get("false_positive_rate"),
        "lora_fpr_probe_false_positive_rate": lora_fpr.get("false_positive_rate"),
        "lora_heldout_parse_ok_rate": lora_heldout.get("parse_ok_rate"),
        "lora_official_parse_ok_rate": lora_official.get("parse_ok_rate"),
        "defense_detect_only_attack_mitigation_rate": defense_detect.get("attack_mitigation_rate"),
        "defense_policy_gate_attack_mitigation_rate": defense_policy.get("attack_mitigation_rate"),
        "defense_orchestrated_attack_mitigation_rate": defense_orch.get("attack_mitigation_rate"),
        "defense_orchestrated_benign_block_rate": defense_orch.get("benign_block_rate"),
        "agent_e2e_stage_count": len(stages),
        "agent_e2e_session_id": data.get("session_id"),
        "agent_e2e_routes": [str(item.get("route")) for item in stages if isinstance(item, dict)],
        "judge_provider_ok_profiles": provider_ok,
        "judge_provider_failed_profiles": provider_failed,
        "judge_provider_skipped_profiles": provider_skipped,
        "judge_provider_ok_count": len(provider_ok),
        "judge_provider_failed_count": len(provider_failed),
        "official_readiness_statuses": readiness_statuses,
        "official_leaderboard_status": readiness_statuses.get("official leaderboard submission"),
        "vlm_probe_ok": data.get("ok"),
        "vlm_probe_status": data.get("status"),
        "vlm_probe_model": data.get("model"),
        "vlm_probe_image_sha256": data.get("image_sha256"),
        "vlm_probe_missing_env": data.get("missing_env") or [],
        "real_executor_session_id": data.get("session_id"),
        "real_executor_case_count": len(real_executor_cases),
        "real_executor_real_execution_count": real_executor_summary.get("real_execution_count"),
        "real_executor_blocked_count": real_executor_summary.get("blocked_count"),
        "real_executor_raw_output_rendered": real_executor_summary.get("raw_output_rendered"),
        "judge_policy_profile_id": data.get("profile_id"),
        "judge_policy_default_judge_only_route": (judge_profile_routes.get("judge_only") or {}).get("route") if isinstance(judge_profile_routes.get("judge_only"), dict) else judge_profile_routes.get("judge_only"),
        "judge_policy_default_agreement_route": (judge_profile_routes.get("runtime_and_judge") or {}).get("route") if isinstance(judge_profile_routes.get("runtime_and_judge"), dict) else judge_profile_routes.get("runtime_and_judge") or judge_profile_routes.get("base_and_judge"),
        "judge_policy_block_threshold": data.get("block_threshold"),
        "judge_policy_review_threshold": data.get("review_threshold"),
        "unified_defense_profile_count": len(unified_profiles),
        "unified_defense_best_profile": unified_best_low_block.get("profile"),
        "unified_defense_best_attack_catch": unified_best_low_block.get("attack_catch"),
        "unified_defense_best_fpr": unified_best_low_block.get("fpr"),
        "unified_defense_best_benign_hard_block": unified_best_low_block.get("benign_hard_block"),
        "unified_defense_scope": data.get("scope"),
        "agent_vlm_case_count": agent_vlm_summary.get("case_count"),
        "agent_vlm_case_pass_rate": agent_vlm_summary.get("case_pass_rate"),
        "agent_vlm_attack_catch": agent_vlm_summary.get("attack_catch"),
        "agent_vlm_fpr": agent_vlm_summary.get("fpr"),
        "agent_vlm_hard_block_fpr": agent_vlm_summary.get("hard_block_fpr"),
        "agent_vlm_benign_allow": agent_vlm_summary.get("benign_allow"),
        "agent_vlm_agent_task_pass_rate": agent_vlm_summary.get("agent_task_pass_rate"),
        "agent_vlm_vlm_case_pass_rate": agent_vlm_summary.get("vlm_case_pass_rate"),
        "agent_vlm_vlm_success_rate": agent_vlm_summary.get("vlm_success_rate"),
        "agent_vlm_disagreement_rate": agent_vlm_summary.get("ocr_vlm_disagreement_rate"),
        "agent_vlm_latency_p95_ms": agent_vlm_summary.get("latency_p95_ms"),
        "agent_vlm_success_rate": agent_vlm_summary.get("success_rate"),
        "xstest_case_count": xstest_summary.get("case_count"),
        "xstest_safe_count": xstest_summary.get("safe_count"),
        "xstest_unsafe_count": xstest_summary.get("unsafe_count"),
        "xstest_safe_fpr": xstest_summary.get("safe_fpr"),
        "xstest_safe_hard_block_rate": xstest_summary.get("safe_hard_block_rate"),
        "xstest_unsafe_contrast_catch": xstest_summary.get("unsafe_contrast_catch"),
        "xstest_provider_success_rate": xstest_summary.get("provider_success_rate"),
        "harmbench_case_count": harmbench_summary.get("case_count") or data.get("case_count"),
        "harmbench_runtime_attack_catch": harmbench_summary.get("attack_catch") or harmbench_runtime.get("attack_catch"),
        "harmbench_runtime_residual_asr": harmbench_summary.get("residual_asr_proxy") or harmbench_runtime.get("residual_asr"),
        "advbench_case_count": advbench_summary.get("case_count"),
        "advbench_runtime_attack_catch": advbench_summary.get("attack_catch"),
        "advbench_runtime_residual_asr": advbench_summary.get("residual_asr_proxy"),
        "advbench_runtime_hard_block_rate": advbench_summary.get("hard_block_rate"),
        "advbench_provider_success_rate": advbench_summary.get("provider_success_rate"),
        "advbench_method_count": len(advbench_methods),
        "advbench_best_recall_method": advbench_best_recall.get("method"),
        "advbench_best_recall_attack_catch": advbench_best_recall.get("attack_catch"),
        "advbench_best_recall_review_rate": advbench_best_recall.get("review_rate"),
        "advbench_best_low_review_method": advbench_best_low_review.get("method"),
        "advbench_best_low_review_attack_catch": advbench_best_low_review.get("attack_catch"),
        "advbench_best_low_review_review_rate": advbench_best_low_review.get("review_rate"),
        "advbench_routed_vs_runtime_delta": data.get("routed_vs_runtime_attack_catch_delta"),
        "jailbreakbench_case_count": jailbreakbench_summary.get("case_count"),
        "jailbreakbench_harmful_count": jailbreakbench_summary.get("harmful_count"),
        "jailbreakbench_benign_count": jailbreakbench_summary.get("benign_count"),
        "jailbreakbench_harmful_signal_catch": jailbreakbench_summary.get("harmful_signal_catch"),
        "jailbreakbench_harmful_residual_asr": jailbreakbench_summary.get("harmful_residual_asr_proxy"),
        "jailbreakbench_benign_fpr": jailbreakbench_summary.get("benign_fpr"),
        "jailbreakbench_benign_hard_block_fpr": jailbreakbench_summary.get("benign_hard_block_fpr"),
        "jailbreakbench_provider_success_rate": jailbreakbench_summary.get("provider_success_rate"),
        "jailbreakbench_dataset_name": jailbreakbench_manifest.get("dataset_name"),
        "jailbreakbench_dataset_hash": jailbreakbench_manifest.get("combined_row_hash_sha256"),
        "jailbreakbench_raw_prompt_rendered": data.get("raw_prompt_rendered"),
        "jailbreakbench_target_rendered": data.get("target_rendered"),
        "jailbreakbench_official_leaderboard_score": data.get("official_leaderboard_score"),
        "jailbreakbench_method_count": len(jailbreakbench_methods),
        "jailbreakbench_best_recall_method": jailbreakbench_best_recall.get("method"),
        "jailbreakbench_best_recall_attack_catch": jailbreakbench_best_recall.get("attack_catch"),
        "jailbreakbench_best_recall_fpr": jailbreakbench_best_recall.get("fpr"),
        "jailbreakbench_best_low_fpr_method": jailbreakbench_best_low_fpr.get("method"),
        "jailbreakbench_best_low_fpr_attack_catch": jailbreakbench_best_low_fpr.get("attack_catch"),
        "jailbreakbench_best_low_fpr_fpr": jailbreakbench_best_low_fpr.get("fpr"),
        "jailbreakbench_deepseek_attack_catch": jailbreakbench_deepseek.get("attack_catch"),
        "jailbreakbench_deepseek_fpr": jailbreakbench_deepseek.get("fpr"),
        "jailbreakbench_qwen_attack_catch": jailbreakbench_qwen.get("attack_catch"),
        "jailbreakbench_qwen_fpr": jailbreakbench_qwen.get("fpr"),
        "jailbreakbench_runtime_attack_catch": jailbreakbench_runtime.get("attack_catch"),
        "jailbreakbench_deepseek_vs_runtime_delta": data.get("deepseek_vs_runtime_attack_catch_delta"),
        "jbb_routing_provider_count": len(jbb_routing_providers),
        "jbb_routing_best_low_hard_block_provider": data.get("best_low_hard_block_provider"),
        "jbb_routing_policy_profile": data.get("policy_profile"),
        "jbb_routing_deepseek_attack_catch": jbb_routing_deepseek_routed.get("attack_catch"),
        "jbb_routing_deepseek_fpr": jbb_routing_deepseek_routed.get("fpr"),
        "jbb_routing_deepseek_review_rate": jbb_routing_deepseek_routed.get("review_rate"),
        "jbb_routing_deepseek_direct_hard_fpr": jbb_routing_deepseek_direct.get("benign_hard_block_rate"),
        "jbb_routing_deepseek_routed_hard_fpr": jbb_routing_deepseek_routed.get("benign_hard_block_rate"),
        "jbb_routing_deepseek_direct_risky_hard_block": jbb_routing_deepseek_direct.get("risky_hard_block_rate"),
        "jbb_routing_deepseek_routed_risky_hard_block": jbb_routing_deepseek_routed.get("risky_hard_block_rate"),
        "jbb_routing_qwen_attack_catch": jbb_routing_qwen_routed.get("attack_catch"),
        "jbb_routing_qwen_fpr": jbb_routing_qwen_routed.get("fpr"),
        "jbb_routing_qwen_review_rate": jbb_routing_qwen_routed.get("review_rate"),
        "jbb_routing_qwen_direct_hard_fpr": jbb_routing_qwen_direct.get("benign_hard_block_rate"),
        "jbb_routing_qwen_routed_hard_fpr": jbb_routing_qwen_routed.get("benign_hard_block_rate"),
        "jbb_routing_qwen_direct_risky_hard_block": jbb_routing_qwen_direct.get("risky_hard_block_rate"),
        "jbb_routing_qwen_routed_risky_hard_block": jbb_routing_qwen_routed.get("risky_hard_block_rate"),
        "jbb_threshold_sweep_row_count": len(jbb_threshold_rows),
        "jbb_threshold_low_provider": jbb_threshold_low.get("provider"),
        "jbb_threshold_low_threshold": jbb_threshold_low.get("threshold"),
        "jbb_threshold_low_attack_catch": jbb_threshold_low.get("attack_catch"),
        "jbb_threshold_low_fpr": jbb_threshold_low.get("fpr"),
        "jbb_threshold_low_review_rate": jbb_threshold_low.get("review_rate"),
        "jbb_threshold_low_hard_fpr": jbb_threshold_low.get("benign_hard_block_rate"),
        "jbb_threshold_high_provider": jbb_threshold_high.get("provider"),
        "jbb_threshold_high_threshold": jbb_threshold_high.get("threshold"),
        "jbb_threshold_high_attack_catch": jbb_threshold_high.get("attack_catch"),
        "jbb_threshold_high_fpr": jbb_threshold_high.get("fpr"),
        "jbb_threshold_high_review_rate": jbb_threshold_high.get("review_rate"),
        "jbb_threshold_high_hard_fpr": jbb_threshold_high.get("benign_hard_block_rate"),
        "jbb_completion_case_count": jbb_completion_summary.get("case_count"),
        "jbb_completion_provider": data.get("provider") if data.get("schema_version") == "guardx-jailbreakbench-completion-scorer-smoke-v1" else None,
        "jbb_completion_model": data.get("model") if data.get("schema_version") == "guardx-jailbreakbench-completion-scorer-smoke-v1" else None,
        "jbb_completion_live_model_invoked": data.get("live_model_invoked") if data.get("schema_version") == "guardx-jailbreakbench-completion-scorer-smoke-v1" else None,
        "jbb_completion_candidate_profile": data.get("candidate_profile") if data.get("schema_version") == "guardx-jailbreakbench-completion-scorer-smoke-v1" else None,
        "jbb_completion_benign_generation_enabled": jbb_completion_summary.get("benign_candidate_generation_enabled"),
        "jbb_completion_recovery_enabled": jbb_completion_summary.get("benign_refusal_recovery_enabled"),
        "jbb_completion_recovery_attempt_count": jbb_completion_summary.get("benign_refusal_recovery_attempt_count"),
        "jbb_completion_recovery_applied_count": jbb_completion_summary.get("benign_refusal_recovery_applied_count"),
        "jbb_completion_provider_success_rate": jbb_completion_summary.get("provider_success_rate"),
        "jbb_completion_parse_ok_rate": jbb_completion_summary.get("parse_ok_rate"),
        "jbb_completion_unsafe_rate": jbb_completion_summary.get("unsafe_completion_rate"),
        "jbb_completion_unsafe_rate_on_risky": jbb_completion_summary.get("unsafe_completion_rate_on_risky"),
        "jbb_completion_unsafe_rate_on_benign": jbb_completion_summary.get("unsafe_completion_rate_on_benign"),
        "jbb_completion_refusal_rate_on_risky": jbb_completion_summary.get("refusal_rate_on_risky"),
        "jbb_completion_refusal_rate_on_benign": jbb_completion_summary.get("refusal_rate_on_benign"),
        "jbb_completion_mean_score": jbb_completion_summary.get("mean_score"),
        "jbb_completion_raw_prompt_rendered": data.get("raw_prompt_rendered"),
        "jbb_completion_grader_text_rendered": data.get("grader_text_rendered"),
        "harm_adv_completion_case_count": harm_adv_completion_summary.get("case_count"),
        "harm_adv_completion_provider": data.get("provider") if data.get("schema_version") == "guardx-harm-adv-completion-scorer-smoke-v1" else None,
        "harm_adv_completion_model": data.get("model") if data.get("schema_version") == "guardx-harm-adv-completion-scorer-smoke-v1" else None,
        "harm_adv_completion_live_model_invoked": data.get("live_model_invoked") if data.get("schema_version") == "guardx-harm-adv-completion-scorer-smoke-v1" else None,
        "harm_adv_completion_provider_success_rate": harm_adv_completion_summary.get("provider_success_rate"),
        "harm_adv_completion_parse_ok_rate": harm_adv_completion_summary.get("parse_ok_rate"),
        "harm_adv_completion_unsafe_rate": harm_adv_completion_summary.get("unsafe_completion_rate"),
        "harm_adv_completion_refusal_rate": harm_adv_completion_summary.get("refusal_rate"),
        "harm_adv_completion_advbench_unsafe_rate": (harm_adv_completion_by_benchmark.get("AdvBench") or {}).get("unsafe_completion_rate")
        if isinstance(harm_adv_completion_by_benchmark.get("AdvBench"), dict)
        else None,
        "harm_adv_completion_harmbench_unsafe_rate": (harm_adv_completion_by_benchmark.get("HarmBench") or {}).get("unsafe_completion_rate")
        if isinstance(harm_adv_completion_by_benchmark.get("HarmBench"), dict)
        else None,
        "harm_adv_completion_raw_prompt_rendered": data.get("raw_prompt_rendered"),
        "harm_adv_completion_grader_text_rendered": data.get("grader_text_rendered"),
        "harmbench_step3_selected_behavior_count": data.get("selected_behavior_count")
        if data.get("schema_version") == "guardx-harmbench-official-completion-manifest-v1"
        else None,
        "harmbench_step3_private_completions_hash": data.get("private_completions_sha256")
        if data.get("schema_version") == "guardx-harmbench-official-completion-manifest-v1"
        else None,
        "harmbench_step3_evaluator_exists": data.get("evaluator_exists")
        if data.get("schema_version") == "guardx-harmbench-official-completion-manifest-v1"
        else None,
        "harmbench_step3_classifier_invoked": harmbench_step3_preflight.get("official_classifier_invoked"),
        "harmbench_step3_leaderboard_score": harmbench_step3_preflight.get("official_leaderboard_score"),
        "harmbench_step3_transformers_available": harmbench_step3_modules.get("transformers"),
        "harmbench_step3_vllm_available": harmbench_step3_modules.get("vllm"),
        "harmbench_step3_spacy_available": harmbench_step3_modules.get("spacy"),
        "harmbench_step3_datasketch_available": harmbench_step3_modules.get("datasketch"),
        "harmbench_step3_spacy_model_available": harmbench_step3_modules.get("en_core_web_sm"),
        "harmbench_step3_blockers": harmbench_step3_preflight.get("step3_blockers") or [],
        "harmbench_step3_behavior_id_rendered": data.get("official_behavior_id_rendered"),
        "harmbench_step3_raw_behavior_rendered": data.get("raw_behavior_rendered"),
        "harmbench_step3_candidate_generation_rendered": data.get("candidate_generation_rendered"),
        "harmbench_step3_importer_preflight_status": data.get("status")
        if data.get("schema_version") == "guardx-harmbench-step3-importer-preflight-v1"
        else None,
        "harmbench_step3_importer_preflight_failed_count": data.get("failed_count")
        if data.get("schema_version") == "guardx-harmbench-step3-importer-preflight-v1"
        else None,
        "harmbench_step3_importer_default_classifier_false": harmbench_step3_importer_checks.get("importer_default_classifier_invoked_false"),
        "harmbench_step3_importer_explicit_classifier_true": harmbench_step3_importer_checks.get("importer_explicit_classifier_invoked_true"),
        "harmbench_step3_importer_runbook_official_flag": harmbench_step3_importer_checks.get("server_runbook_passes_official_flag"),
        "harmbench_step3_importer_private_hash_match": harmbench_step3_importer_checks.get("private_completions_sha_matches_manifest"),
        "harmbench_step3_result_case_count": harmbench_step3_result_summary.get("case_count"),
        "harmbench_step3_result_valid_label_count": harmbench_step3_result_summary.get("valid_label_count"),
        "harmbench_step3_result_official_asr": harmbench_step3_result_summary.get("official_asr"),
        "harmbench_step3_result_safe_refusal_rate": harmbench_step3_result_summary.get("safe_refusal_rate_proxy"),
        "harmbench_step3_result_invalid_label_rate": harmbench_step3_result_summary.get("invalid_label_rate"),
        "harmbench_step3_result_classifier_invoked": data.get("official_classifier_invoked")
        if data.get("schema_version") == "guardx-harmbench-official-step3-result-summary-v1"
        else None,
        "harmbench_step3_result_leaderboard_score": data.get("official_leaderboard_score")
        if data.get("schema_version") == "guardx-harmbench-official-step3-result-summary-v1"
        else None,
        "harmbench_step3_result_raw_behavior_id_rendered": data.get("raw_behavior_id_rendered")
        if data.get("schema_version") == "guardx-harmbench-official-step3-result-summary-v1"
        else None,
        "harmbench_step3_result_generation_rendered": data.get("generation_rendered")
        if data.get("schema_version") == "guardx-harmbench-official-step3-result-summary-v1"
        else None,
        "harmbench_step3_result_guard_ready": data.get("ready")
        if data.get("schema_version") == "guardx-harmbench-step3-result-guard-v1"
        else None,
        "harmbench_step3_result_guard_transition_state": data.get("transition_state")
        if data.get("schema_version") == "guardx-harmbench-step3-result-guard-v1"
        else None,
        "harmbench_step3_result_guard_check_count": data.get("check_count")
        if data.get("schema_version") == "guardx-harmbench-step3-result-guard-v1"
        else None,
        "harmbench_step3_result_guard_failed_count": data.get("failed_count")
        if data.get("schema_version") == "guardx-harmbench-step3-result-guard-v1"
        else None,
        "harmbench_step3_result_guard_public_summary_exists": data.get("public_result_summary_exists")
        if data.get("schema_version") == "guardx-harmbench-step3-result-guard-v1"
        else None,
        "harmbench_step3_result_guard_private_result_exists": data.get("private_result_exists")
        if data.get("schema_version") == "guardx-harmbench-step3-result-guard-v1"
        else None,
        "harmbench_step3_result_guard_no_private_waiting": harmbench_step3_result_guard_checks.get("no_private_result_waiting_without_import"),
        "harmbench_step3_result_guard_hash_only_if_present": harmbench_step3_result_guard_checks.get("imported_result_hash_only_if_present"),
        "harmbench_step3_result_guard_leaderboard_score": data.get("official_leaderboard_score")
        if data.get("schema_version") == "guardx-harmbench-step3-result-guard-v1"
        else None,
        "harmbench_method_count": len(harmbench_methods),
        "harmbench_best_method": harmbench_best.get("method"),
        "harmbench_best_attack_catch": harmbench_best.get("attack_catch"),
        "harmbench_best_residual_asr": harmbench_best.get("residual_asr"),
        "harmbench_qwen_attack_catch": harmbench_qwen.get("attack_catch"),
        "harmbench_qwen_latency_p95_ms": harmbench_qwen.get("latency_p95_ms"),
        "harmbench_qwen_provider_success": harmbench_qwen.get("provider_success_rate"),
        "harmbench_qwen_vs_runtime_delta": data.get("qwen_vs_runtime_attack_catch_delta"),
        "judge_tradeoff_method_count": len(judge_tradeoff_methods),
        "judge_tradeoff_balanced_provider": judge_tradeoff_balanced.get("method"),
        "judge_tradeoff_low_fpr_provider": judge_tradeoff_low_fpr.get("method"),
        "judge_tradeoff_high_recall_provider": judge_tradeoff_high_recall.get("method"),
        "judge_tradeoff_deepseek_harmbench_attack_catch": judge_tradeoff_deepseek.get("harmbench_attack_catch"),
        "judge_tradeoff_deepseek_xstest_fpr": judge_tradeoff_deepseek.get("xstest_safe_fpr"),
        "judge_tradeoff_deepseek_xstest_unsafe_catch": judge_tradeoff_deepseek.get("xstest_unsafe_contrast_catch"),
        "judge_tradeoff_qwen_harmbench_attack_catch": judge_tradeoff_qwen.get("harmbench_attack_catch"),
        "judge_tradeoff_qwen_xstest_fpr": judge_tradeoff_qwen.get("xstest_safe_fpr"),
        "judge_tradeoff_qwen_xstest_unsafe_catch": judge_tradeoff_qwen.get("xstest_unsafe_contrast_catch"),
        "judge_routing_provider_count": len(judge_routing_providers),
        "judge_routing_best_low_hard_block_provider": data.get("best_low_hard_block_provider"),
        "judge_routing_deepseek_harmbench_attack_catch": judge_routing_deepseek_routed_harm.get("attack_catch"),
        "judge_routing_deepseek_xstest_fpr": judge_routing_deepseek_routed_xstest.get("fpr"),
        "judge_routing_deepseek_xstest_hard_fpr": judge_routing_deepseek_routed_xstest.get("benign_hard_block_rate"),
        "judge_routing_deepseek_direct_hard_fpr": judge_routing_deepseek_direct_xstest.get("benign_hard_block_rate"),
        "judge_routing_qwen_harmbench_attack_catch": judge_routing_qwen_routed_harm.get("attack_catch"),
        "judge_routing_qwen_xstest_fpr": judge_routing_qwen_routed_xstest.get("fpr"),
        "judge_routing_qwen_xstest_hard_fpr": judge_routing_qwen_routed_xstest.get("benign_hard_block_rate"),
        "judge_routing_qwen_direct_hard_fpr": judge_routing_qwen_direct_xstest.get("benign_hard_block_rate"),
        "vlm_multi_image_count": vlm_multi_image_summary.get("image_count"),
        "vlm_multi_provider_row_count": vlm_multi_image_summary.get("provider_row_count"),
        "vlm_multi_provider_success_rate": vlm_multi_image_summary.get("provider_success_rate"),
        "vlm_multi_attack_catch": vlm_multi_image_summary.get("image_level_attack_catch"),
        "vlm_multi_fpr": vlm_multi_image_summary.get("image_level_fpr_review_or_block"),
        "vlm_multi_hard_block_fpr": vlm_multi_image_summary.get("image_level_hard_block_fpr"),
        "vlm_multi_disagreement_rate": vlm_multi_image_summary.get("ocr_vlm_risk_hint_disagreement_rate"),
        "agent_task_graph_scenario_count": agent_task_graph_summary.get("scenario_count"),
        "agent_task_graph_node_count": agent_task_graph_summary.get("node_count"),
        "agent_task_graph_edge_count": agent_task_graph_summary.get("edge_count"),
        "agent_task_graph_private_asset_cases": agent_task_graph_summary.get("cases_with_private_assets"),
        "agent_graph_alignment_case_count": agent_task_graph_alignment_summary.get("case_count"),
        "agent_graph_alignment_action_count": agent_task_graph_alignment_summary.get("action_node_count"),
        "agent_graph_alignment_pass_rate": agent_task_graph_alignment_summary.get("alignment_pass_rate"),
        "agent_graph_alignment_security_block": agent_task_graph_alignment_summary.get("security_block_rate"),
        "agent_graph_alignment_utility_allow": agent_task_graph_alignment_summary.get("utility_allow_rate"),
        "agent_graph_alignment_benign_block": agent_task_graph_alignment_summary.get("benign_block_rate"),
        "agent_graph_alignment_all_aligned": agent_task_graph_alignment_summary.get("all_case_graphs_aligned"),
        "official_parity_benchmark_count": len(official_parity_rows),
        "official_parity_ready_count": len(official_parity_ready),
        "official_parity_ready_benchmarks": [str(row.get("benchmark")) for row in official_parity_ready],
        "official_parity_local_evidence_count": len(official_parity_local_evidence),
        "official_parity_local_evidence_benchmarks": [str(row.get("benchmark")) for row in official_parity_local_evidence],
        "official_parity_missing_expected_files_count": len(official_parity_missing_expected_files),
        "official_parity_missing_expected_files": official_parity_missing_expected_files,
        "official_parity_leaderboard_score": data.get("official_leaderboard_score"),
        "official_parity_xstest_ready": official_parity_xstest.get("ready_for_local_official_reproduction"),
        "official_ledger_row_count": len(official_ledger_rows),
        "official_ledger_family_count": data.get("benchmark_family_count") or len(official_ledger_summaries),
        "official_ledger_summary_benchmarks": sorted(str(key) for key in official_ledger_summaries.keys()),
        "official_ledger_required_files_ok": data.get("required_files_ok"),
        "official_ledger_no_raw_prompt_rendered": data.get("no_raw_prompt_rendered"),
        "official_ledger_leaderboard_score": data.get("official_leaderboard_score"),
        "official_ledger_benchmarks": [str(row.get("benchmark")) for row in official_ledger_rows if isinstance(row, dict)],
        "official_ledger_xstest_safe_fpr": official_ledger_xstest_metrics.get("safe_fpr"),
        "official_ledger_xstest_safe_hard_block": official_ledger_xstest_metrics.get("safe_hard_block_rate"),
        "official_ledger_harmbench_attack_catch": official_ledger_harmbench_metrics.get("attack_catch"),
        "official_ledger_jailbreakbench_harmful_signal_catch": official_ledger_jailbreakbench_metrics.get("harmful_signal_catch"),
        "official_ledger_jailbreakbench_benign_fpr": official_ledger_jailbreakbench_metrics.get("benign_fpr"),
        "official_ledger_agent_alignment": official_ledger_agent_metrics.get("alignment_pass_rate"),
        "upstream_check_benchmark_count": len(upstream_check_rows) or data.get("benchmark_count"),
        "upstream_check_status_counts": upstream_check_status_counts,
        "upstream_check_upstream_ready_count": len(upstream_check_ready),
        "upstream_check_local_data_only_count": len(upstream_check_data_only),
        "upstream_check_repo_like_count": len(upstream_check_repo_like),
        "upstream_check_proxy_missing_count": len(upstream_check_proxy_missing),
        "upstream_check_ready_benchmarks": [str(row.get("benchmark")) for row in upstream_check_ready],
        "upstream_check_data_only_benchmarks": [str(row.get("benchmark")) for row in upstream_check_data_only],
        "upstream_check_repo_like_benchmarks": [str(row.get("benchmark")) for row in upstream_check_repo_like],
        "upstream_check_local_root": data.get("local_root"),
        "upstream_check_leaderboard_score": data.get("official_leaderboard_score"),
        "upstream_check_raw_prompt_rendered": data.get("raw_prompt_rendered"),
        "upstream_smoke_benchmark_count": len(upstream_smoke_rows) or data.get("benchmark_count"),
        "upstream_smoke_ready_count": len(upstream_smoke_ready) or data.get("smoke_ready_count"),
        "upstream_smoke_compile_ready_count": len(upstream_smoke_compile_ok),
        "upstream_smoke_data_ready_count": len(upstream_smoke_data_ready),
        "upstream_smoke_ready_benchmarks": [str(row.get("benchmark")) for row in upstream_smoke_ready],
        "upstream_smoke_raw_prompt_rendered": data.get("raw_prompt_rendered"),
        "upstream_smoke_leaderboard_score": data.get("official_leaderboard_score"),
        "upstream_smoke_claim_boundary": data.get("claim_boundary"),
        "strongreject_cloud_ready": data.get("official_cloud_ready"),
        "strongreject_autograder_invoked": data.get("official_autograder_invoked"),
        "strongreject_full_dataset_rows": strongreject_full.get("row_count"),
        "strongreject_small_dataset_rows": strongreject_small.get("row_count"),
        "strongreject_missing_for_cloud_run": data.get("missing_for_cloud_run") or [],
        "strongreject_refusal_parse_ok": strongreject_refusal.get("parse_ok"),
        "strongreject_non_refusal_parse_ok": strongreject_non_refusal.get("parse_ok"),
        "strongreject_non_refusal_score": strongreject_non_refusal.get("score"),
        "strongreject_raw_prompt_rendered": data.get("raw_prompt_rendered"),
        "strongreject_adapter_case_count": strongreject_adapter_summary.get("case_count"),
        "strongreject_adapter_risk_signal_rate": strongreject_adapter_summary.get("risk_signal_detected_rate"),
        "strongreject_adapter_route_gap_rate": strongreject_adapter_summary.get("runtime_to_adapter_route_gap_rate"),
        "strongreject_adapter_prevented_rate": strongreject_adapter_summary.get("pre_generation_prevented_rate"),
        "strongreject_adapter_hard_block_rate": strongreject_adapter_summary.get("hard_block_rate"),
        "strongreject_adapter_review_rate": strongreject_adapter_summary.get("review_rate"),
        "strongreject_adapter_live_score_count": strongreject_adapter_summary.get("live_official_score_count"),
        "strongreject_adapter_live_autograder_invoked": data.get("live_official_autograder_invoked"),
        "strongreject_adapter_policy_profile": data.get("adapter_policy_profile"),
        "strongreject_adapter_raw_prompt_rendered": data.get("raw_prompt_rendered"),
        "strongreject_adapter_target_response_rendered": data.get("target_response_rendered"),
        "strongreject_scorer_case_count": strongreject_scorer_summary.get("case_count"),
        "strongreject_scorer_provider": data.get("provider"),
        "strongreject_scorer_model": data.get("model"),
        "strongreject_scorer_live_model_invoked": data.get("live_model_invoked"),
        "strongreject_scorer_provider_success_rate": strongreject_scorer_summary.get("provider_success_rate"),
        "strongreject_scorer_parse_ok_rate": strongreject_scorer_summary.get("parse_ok_rate"),
        "strongreject_scorer_score_count": strongreject_scorer_summary.get("score_count"),
        "strongreject_scorer_mean_score": strongreject_scorer_summary.get("mean_score"),
        "strongreject_scorer_raw_prompt_rendered": data.get("raw_prompt_rendered"),
        "strongreject_scorer_target_response_rendered": data.get("target_response_rendered"),
        "strongreject_scorer_grader_text_rendered": data.get("grader_text_rendered"),
        "benign_recovery_train_total": benign_recovery_train.get("total"),
        "benign_recovery_eval_total": benign_recovery_eval.get("total"),
        "benign_recovery_train_labels": benign_recovery_train.get("label_counts"),
        "benign_recovery_eval_labels": benign_recovery_eval.get("label_counts"),
        "benign_recovery_raw_prompt_policy": data.get("raw_prompt_policy"),
        "benign_recovery_contains_real_pii": data.get("contains_real_pii"),
        "same_batch_method_count": len(same_batch_methods),
        "same_batch_max_case_count": data.get("max_method_case_count") or max((int(item.get("cases", 0) or 0) for item in same_batch_methods.values() if isinstance(item, dict)), default=0),
        "same_batch_complete_methods": same_batch_complete_methods,
        "same_batch_partial_methods": same_batch_partial_methods,
        "same_batch_default_profile": same_batch_default_profile,
        "same_batch_default_working_point": data.get("default_working_point"),
        "same_batch_full_attack_catch": same_batch_full.get("attack_catch"),
        "same_batch_full_fpr": same_batch_full.get("fpr"),
        "same_batch_full_review_rate": same_batch_full.get("review_rate"),
        "same_batch_full_benign_hard_block": same_batch_full.get("benign_hard_block"),
        "same_batch_judge_attack_catch": same_batch_judge.get("attack_catch"),
        "same_batch_judge_fpr": same_batch_judge.get("fpr"),
        "same_batch_judge_review_rate": same_batch_judge.get("review_rate"),
        "same_batch_lora_attack_catch": same_batch_lora.get("attack_catch"),
        "same_batch_lora_fpr": same_batch_lora.get("fpr"),
        "same_batch_runtime_attack_catch": same_batch_runtime.get("attack_catch"),
        "same_batch_runtime_fpr": same_batch_runtime.get("fpr"),
        "lora_routing_standalone_attack_catch": lora_routing_standalone.get("attack_catch"),
        "lora_routing_standalone_fpr": lora_routing_standalone.get("fpr"),
        "lora_routing_routed_attack_catch": lora_routing_routed.get("attack_catch"),
        "lora_routing_routed_fpr": lora_routing_routed.get("fpr"),
        "lora_routing_layer_attack_catch": lora_routing_layer.get("attack_catch"),
        "lora_routing_layer_fpr": lora_routing_layer.get("fpr"),
        "lora_routing_layer_benign_hard_block": lora_routing_layer.get("benign_hard_block"),
        "lora_routing_delta_standalone_vs_routed": lora_routing_delta.get("standalone_minus_routed_attack_catch"),
        "lora_routing_delta_layer_vs_routed": lora_routing_delta.get("layer_aware_minus_routed_attack_catch"),
        "lora_routing_claim_boundary": data.get("claim_boundary"),
        "final_gate_status": data.get("status")
        if data.get("schema_version") == "guardx-final-submission-gate-v1"
        else None,
        "final_gate_check_count": data.get("check_count")
        if data.get("schema_version") == "guardx-final-submission-gate-v1"
        else None,
        "final_gate_failed_count": data.get("failed_count")
        if data.get("schema_version") == "guardx-final-submission-gate-v1"
        else None,
        "final_gate_failed_items": [str(row.get("item")) for row in final_gate_failed[:5]],
        "final_gate_claim_boundary": data.get("claim_boundary")
        if data.get("schema_version") == "guardx-final-submission-gate-v1"
        else None,
        "portal_rehearsal_page_status": portal_rehearsal.get("page_status"),
        "portal_rehearsal_page_title": portal_rehearsal.get("page_title"),
        "portal_rehearsal_health_state": portal_rehearsal_health.get("state"),
        "portal_rehearsal_missing_kinds": portal_rehearsal_health.get("missing_kinds") or [],
        "portal_rehearsal_failed_kinds": portal_rehearsal_health.get("failed_kinds") or [],
        "portal_rehearsal_final_gate_required": portal_rehearsal_health.get("final_submission_gate_required"),
        "portal_rehearsal_final_gate_status": portal_rehearsal_gate.get("status"),
        "portal_rehearsal_final_gate_checks": portal_rehearsal_gate.get("check_count"),
        "portal_rehearsal_final_gate_failed": portal_rehearsal_gate.get("failed_count"),
        "portal_rehearsal_rendered_card_count": len(portal_rehearsal_cards),
        "portal_rehearsal_final_gate_card": portal_rehearsal_cards.get("artifactFinalGate"),
        "portal_rehearsal_screenshot_sha256": portal_rehearsal_screenshot.get("sha256"),
        "portal_rehearsal_screenshot_committed": portal_rehearsal_screenshot.get("committed_to_repo"),
        "presentation_freshness_ready": presentation_freshness.get("ready"),
        "presentation_freshness_deck_count": presentation_freshness.get("deck_count") or len(presentation_decks),
        "presentation_freshness_slide_count": presentation_freshness.get("slide_count"),
        "presentation_freshness_stale_hit_count": presentation_stale_count,
        "presentation_freshness_missing_required_count": presentation_missing_count,
        "presentation_freshness_secret_like_count": presentation_secret_like_count,
        "presentation_freshness_gate_checks": (presentation_freshness.get("source_metrics") or {}).get("final_gate_check_count")
        if isinstance(presentation_freshness.get("source_metrics"), dict)
        else None,
        "presentation_freshness_audit_checks": (presentation_freshness.get("source_metrics") or {}).get("submission_audit_check_count")
        if isinstance(presentation_freshness.get("source_metrics"), dict)
        else None,
        "presentation_freshness_package_files": (presentation_freshness.get("source_metrics") or {}).get("package_tracked_file_count")
        if isinstance(presentation_freshness.get("source_metrics"), dict)
        else None,
        "presentation_freshness_portal_cards": (presentation_freshness.get("source_metrics") or {}).get("portal_card_count")
        if isinstance(presentation_freshness.get("source_metrics"), dict)
        else None,
        "presentation_freshness_official_leaderboard_score": presentation_freshness.get("official_leaderboard_score"),
        "presentation_freshness_award_claimed": presentation_freshness.get("award_claimed"),
        "presentation_freshness_claim_boundary": presentation_freshness.get("claim_boundary"),
        "demo_flow_summary_ready": demo_flow_summary.get("ready"),
        "final_demo_story_count": demo_flow_summary.get("story_count") or len(final_demo_stories),
        "final_demo_story_ids": [str(item.get("story_id")) for item in final_demo_stories if isinstance(item, dict)],
        "final_demo_raw_prompt_rendered": demo_flow_summary.get("raw_prompt_rendered"),
        "final_demo_real_private_data_rendered": demo_flow_summary.get("real_private_data_rendered"),
        "competition_submission_audit_ready": competition_submission_audit.get("ready"),
        "competition_submission_audit_check_count": competition_submission_audit.get("check_count"),
        "competition_submission_audit_failed_count": competition_submission_audit.get("failed_count"),
        "claim_defense_ready": claim_defense_matrix.get("ready"),
        "claim_defense_item_count": claim_defense_matrix.get("item_count") or len(claim_defense_items),
        "claim_defense_unresolved_count": claim_defense_matrix.get("unresolved_count"),
        "claim_defense_raw_prompt_rendered": claim_defense_matrix.get("raw_prompt_rendered"),
        "claim_defense_real_private_data_rendered": claim_defense_matrix.get("real_private_data_rendered"),
        "claim_defense_public_package_status": claim_defense_matrix.get("public_package_status"),
        "claim_defense_final_gate_status": claim_defense_matrix.get("final_gate_status"),
        "claim_defense_claim_boundary": claim_defense_matrix.get("claim_boundary"),
        "final_rehearsal_ready": final_rehearsal_runbook.get("ready"),
        "final_rehearsal_command_count": len(final_rehearsal_commands),
        "final_rehearsal_pitch_count": len(final_rehearsal_pitch),
        "final_rehearsal_pitch_total_seconds": final_rehearsal_runbook.get("pitch_total_seconds"),
        "final_rehearsal_flow_count": len(final_rehearsal_flow),
        "final_rehearsal_qna_count": len(final_rehearsal_qna),
        "final_rehearsal_raw_prompt_rendered": final_rehearsal_runbook.get("raw_prompt_rendered"),
        "final_rehearsal_real_private_data_rendered": final_rehearsal_runbook.get("real_private_data_rendered"),
        "final_rehearsal_final_gate_checks": (final_rehearsal_runbook.get("headline_metrics") or {}).get("final_gate_checks") if isinstance(final_rehearsal_runbook.get("headline_metrics"), dict) else None,
        "final_rehearsal_claim_boundary": final_rehearsal_runbook.get("claim_boundary"),
        "official_submission_handoff_ready": official_submission_handoff.get("ready"),
        "official_submission_handoff_manual_count": official_submission_handoff.get("manual_item_count") or len(official_submission_manual_items),
        "official_submission_handoff_manual_pending_count": official_submission_handoff.get("manual_pending_count"),
        "official_submission_handoff_source_count": len(official_submission_sources),
        "official_submission_handoff_claimed": official_submission_handoff.get("official_submission_claimed"),
        "official_submission_handoff_raw_prompt_rendered": official_submission_handoff.get("raw_prompt_rendered"),
        "official_submission_handoff_real_private_data_rendered": official_submission_handoff.get("real_private_data_rendered"),
        "official_submission_handoff_claim_boundary": official_submission_handoff.get("claim_boundary"),
        "final_demo_video_ready": demo_recording_plan.get("ready"),
        "final_demo_video_shot_count": demo_recording_plan.get("shot_count") or len(final_demo_video_shots),
        "final_demo_video_target_seconds": demo_recording_plan.get("target_duration_seconds"),
        "final_demo_video_recording_check_count": demo_recording_plan.get("recording_manual_item_count") or len(final_demo_video_recording_checks),
        "final_demo_video_portal_cards_available": demo_recording_plan.get("portal_cards_available"),
        "final_demo_video_raw_prompt_rendered": demo_recording_plan.get("raw_prompt_rendered"),
        "final_demo_video_real_private_data_rendered": demo_recording_plan.get("real_private_data_rendered"),
        "final_demo_video_official_submission_claimed": demo_recording_plan.get("official_submission_claimed"),
        "final_demo_video_claim_boundary": demo_recording_plan.get("claim_boundary"),
        "final_packet_cover_ready": final_packet_cover.get("ready"),
        "final_packet_cover_upload_item_count": final_packet_cover.get("upload_item_count") or len(final_packet_upload_items),
        "final_packet_cover_manual_after_upload_count": final_packet_cover.get("manual_after_upload_count") or len(final_packet_manual_items),
        "final_packet_cover_git_commit": final_packet_cover.get("git_commit_at_generation") or final_packet_cover.get("git_commit"),
        "final_packet_cover_final_commit_source": final_packet_cover.get("final_commit_source"),
        "final_packet_cover_raw_prompt_rendered": final_packet_cover.get("raw_prompt_rendered"),
        "final_packet_cover_real_private_data_rendered": final_packet_cover.get("real_private_data_rendered"),
        "final_packet_cover_official_submission_claimed": final_packet_cover.get("official_submission_claimed"),
        "final_packet_cover_official_leaderboard_score": final_packet_cover.get("official_leaderboard_score"),
        "final_packet_cover_award_claimed": final_packet_cover.get("award_claimed"),
        "final_packet_cover_claim_boundary": final_packet_cover.get("claim_boundary"),
        "judge_rubric_ready": judge_rubric_scorecard.get("ready"),
        "judge_rubric_local_evidence_score": judge_rubric_scorecard.get("local_evidence_score"),
        "judge_rubric_total_weight": judge_rubric_scorecard.get("total_weight"),
        "judge_rubric_score_ratio": judge_rubric_scorecard.get("score_ratio"),
        "judge_rubric_dimension_count": judge_rubric_scorecard.get("dimension_count") or len(judge_rubric_dimensions),
        "judge_rubric_passed_dimension_count": judge_rubric_scorecard.get("passed_dimension_count"),
        "judge_rubric_failed_dimensions": judge_rubric_scorecard.get("failed_dimensions") or [],
        "judge_rubric_non_claim_count": len(judge_rubric_non_claims),
        "judge_rubric_raw_prompt_rendered": judge_rubric_scorecard.get("raw_prompt_rendered"),
        "judge_rubric_real_private_data_rendered": judge_rubric_scorecard.get("real_private_data_rendered"),
        "judge_rubric_official_leaderboard_score": judge_rubric_scorecard.get("official_leaderboard_score"),
        "judge_rubric_award_claimed": judge_rubric_scorecard.get("award_claimed"),
        "judge_rubric_claim_boundary": judge_rubric_scorecard.get("claim_boundary"),
        "benchmark_traceability_ready": benchmark_traceability.get("ready"),
        "benchmark_traceability_row_count": benchmark_traceability.get("row_count"),
        "benchmark_traceability_ready_row_count": benchmark_traceability.get("ready_row_count"),
        "benchmark_traceability_family_count": benchmark_traceability.get("benchmark_family_count"),
        "benchmark_traceability_method_count": benchmark_traceability.get("distinct_method_count"),
        "benchmark_traceability_evidence_file_count": benchmark_traceability.get("evidence_file_count"),
        "benchmark_traceability_missing_evidence_count": benchmark_traceability.get("missing_evidence_count"),
        "benchmark_traceability_same_batch_or_boundary_explained": benchmark_traceability.get("same_batch_or_boundary_explained"),
        "benchmark_traceability_raw_prompt_rendered": benchmark_traceability.get("raw_prompt_rendered"),
        "benchmark_traceability_real_private_data_rendered": benchmark_traceability.get("real_private_data_rendered"),
        "benchmark_traceability_official_leaderboard_score": benchmark_traceability.get("official_leaderboard_score"),
        "benchmark_traceability_claim_boundary": benchmark_traceability.get("claim_boundary"),
        "final_live_demo_scorecard_ready": final_live_demo_scorecard.get("ready"),
        "final_live_demo_scorecard_check_count": final_live_demo_scorecard.get("check_count"),
        "final_live_demo_scorecard_failed_count": final_live_demo_scorecard.get("failed_count"),
        "final_live_demo_scorecard_story_count": final_live_demo_scorecard.get("story_count"),
        "final_live_demo_scorecard_portal_story_card_count": final_live_demo_scorecard.get("portal_story_card_count"),
        "final_live_demo_scorecard_shot_count": final_live_demo_scorecard.get("shot_count"),
        "final_live_demo_scorecard_pitch_section_count": final_live_demo_scorecard.get("pitch_section_count"),
        "final_live_demo_scorecard_pitch_total_seconds": final_live_demo_scorecard.get("pitch_total_seconds"),
        "final_live_demo_scorecard_qna_count": final_live_demo_scorecard.get("qna_count"),
        "final_live_demo_scorecard_recording_check_count": final_live_demo_scorecard.get("recording_check_count"),
        "final_live_demo_scorecard_portal_card_count": final_live_demo_scorecard.get("portal_card_count"),
        "final_live_demo_scorecard_raw_prompt_rendered": final_live_demo_scorecard.get("raw_prompt_rendered"),
        "final_live_demo_scorecard_real_private_data_rendered": final_live_demo_scorecard.get("real_private_data_rendered"),
        "final_live_demo_scorecard_official_submission_claimed": final_live_demo_scorecard.get("official_submission_claimed"),
        "final_live_demo_scorecard_official_leaderboard_score": final_live_demo_scorecard.get("official_leaderboard_score"),
        "final_live_demo_scorecard_claim_boundary": final_live_demo_scorecard.get("claim_boundary"),
        "evidence_readiness_ready": data.get("ready")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        else None,
        "evidence_readiness_score": data.get("local_evidence_score")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        else None,
        "evidence_readiness_total_weight": data.get("total_weight")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        else None,
        "evidence_readiness_dimension_count": data.get("dimension_count")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        else None,
        "evidence_readiness_passed_dimension_count": data.get("passed_dimension_count")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        else None,
        "evidence_readiness_watch_count": data.get("watch_count")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        else None,
        "evidence_readiness_critical_open_count": data.get("critical_open_count")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        else None,
        "evidence_readiness_attack_catch": (data.get("headline_metrics") or {}).get("guardx_attack_catch")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        and isinstance(data.get("headline_metrics"), dict)
        else None,
        "evidence_readiness_fpr": (data.get("headline_metrics") or {}).get("guardx_fpr")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        and isinstance(data.get("headline_metrics"), dict)
        else None,
        "evidence_readiness_benign_hard_block": (data.get("headline_metrics") or {}).get("guardx_benign_hard_block")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        and isinstance(data.get("headline_metrics"), dict)
        else None,
        "evidence_readiness_raw_prompt_rendered": data.get("raw_prompt_rendered")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        else None,
        "evidence_readiness_real_private_data_rendered": data.get("real_private_data_rendered")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        else None,
        "evidence_readiness_official_submission_claimed": data.get("official_submission_claimed")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        else None,
        "evidence_readiness_official_leaderboard_score": data.get("official_leaderboard_score")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        else None,
        "evidence_readiness_award_claimed": data.get("award_claimed")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        else None,
        "evidence_readiness_claim_boundary": data.get("claim_boundary")
        if data.get("schema_version") == "guardx-evidence-readiness-board-v1"
        else None,
        "defense_evidence_notes_ready": data.get("ready")
        if data.get("schema_version") == "guardx-defense-evidence-notes-v1"
        else None,
        "defense_evidence_notes_opening_count": data.get("opening_line_count")
        if data.get("schema_version") == "guardx-defense-evidence-notes-v1"
        else None,
        "defense_evidence_notes_story_count": data.get("demo_story_count")
        if data.get("schema_version") == "guardx-defense-evidence-notes-v1"
        else None,
        "defense_evidence_notes_number_count": data.get("number_count")
        if data.get("schema_version") == "guardx-defense-evidence-notes-v1"
        else None,
        "defense_evidence_notes_qna_count": data.get("qna_count")
        if data.get("schema_version") == "guardx-defense-evidence-notes-v1"
        else None,
        "defense_evidence_notes_do_not_say_count": data.get("do_not_say_count")
        if data.get("schema_version") == "guardx-defense-evidence-notes-v1"
        else None,
        "defense_evidence_notes_fallback_count": data.get("fallback_count")
        if data.get("schema_version") == "guardx-defense-evidence-notes-v1"
        else None,
        "defense_evidence_notes_raw_prompt_rendered": data.get("raw_prompt_rendered")
        if data.get("schema_version") == "guardx-defense-evidence-notes-v1"
        else None,
        "defense_evidence_notes_real_private_data_rendered": data.get("real_private_data_rendered")
        if data.get("schema_version") == "guardx-defense-evidence-notes-v1"
        else None,
        "defense_evidence_notes_official_submission_claimed": data.get("official_submission_claimed")
        if data.get("schema_version") == "guardx-defense-evidence-notes-v1"
        else None,
        "defense_evidence_notes_official_leaderboard_score": data.get("official_leaderboard_score")
        if data.get("schema_version") == "guardx-defense-evidence-notes-v1"
        else None,
        "defense_evidence_notes_award_claimed": data.get("award_claimed")
        if data.get("schema_version") == "guardx-defense-evidence-notes-v1"
        else None,
        "defense_evidence_notes_claim_boundary": data.get("claim_boundary")
        if data.get("schema_version") == "guardx-defense-evidence-notes-v1"
        else None,
        "submission_package_status": submission_package.get("status"),
        "submission_package_tracked_file_count": submission_package.get("tracked_file_count"),
        "submission_package_tracked_size_mb": submission_package.get("tracked_size_mb"),
        "submission_package_forbidden_count": submission_package.get("forbidden_tracked_count"),
        "submission_package_required_missing_count": submission_package.get("required_missing_count"),
        "submission_package_secret_hit_count": submission_package.get("secret_scan_hit_count"),
        "submission_package_private_raw_count": submission_package.get("private_raw_tracked_count"),
        "submission_package_raw_text_hint_count": submission_package.get("raw_text_field_hint_count"),
        "submission_package_local_path_hint_count": submission_package.get("local_path_hint_count"),
        "submission_package_claim_boundary": submission_package.get("claim_boundary"),
        "reviewer_reproduction_ready": reviewer_reproduction.get("ready"),
        "reviewer_reproduction_command_count": reviewer_reproduction.get("command_count"),
        "reviewer_reproduction_p0_count": reviewer_reproduction.get("p0_command_count"),
        "reviewer_reproduction_missing_evidence_count": reviewer_reproduction.get("missing_evidence_count"),
        "reviewer_reproduction_missing_script_count": reviewer_reproduction.get("missing_script_count"),
        "reviewer_reproduction_secret_command_count": reviewer_reproduction.get("secret_command_count"),
        "reviewer_reproduction_api_key_command_count": reviewer_reproduction.get("api_key_command_count"),
        "reviewer_reproduction_estimated_minutes": reviewer_reproduction.get("estimated_total_minutes"),
        "reviewer_reproduction_raw_prompt_rendered": reviewer_reproduction.get("raw_prompt_rendered"),
        "reviewer_reproduction_real_private_data_rendered": reviewer_reproduction.get("real_private_data_rendered"),
        "reviewer_reproduction_official_leaderboard_score": reviewer_reproduction.get("official_leaderboard_score"),
        "reviewer_reproduction_official_submission_claimed": reviewer_reproduction.get("official_submission_claimed"),
        "reviewer_reproduction_award_claimed": reviewer_reproduction.get("award_claimed"),
        "reviewer_reproduction_claim_boundary": reviewer_reproduction.get("claim_boundary"),
        "public_archive_review_scan_ready": public_archive_review_scan.get("ready"),
        "public_archive_review_scan_entry_count": public_archive_review_scan.get("entry_count"),
        "public_archive_review_scan_required_entry_count": public_archive_review_scan.get("required_entry_count"),
        "public_archive_review_scan_missing_required_count": public_archive_review_scan.get("missing_required_count"),
        "public_archive_review_scan_boundary_missing_count": public_archive_review_scan.get("boundary_phrase_missing_count"),
        "public_archive_review_scan_secret_hit_count": public_archive_review_scan.get("secret_hit_count"),
        "public_archive_review_scan_stale_hit_count": public_archive_review_scan.get("stale_hit_count"),
        "public_archive_review_scan_overclaim_hit_count": public_archive_review_scan.get("forbidden_overclaim_hit_count"),
        "public_archive_review_scan_manifest_hash_matches": public_archive_review_scan.get("manifest_hash_matches"),
        "public_archive_review_scan_claim_boundary": public_archive_review_scan.get("claim_boundary"),
        "public_archive_reproduction_smoke_ready": public_archive_reproduction_smoke.get("ready"),
        "public_archive_reproduction_smoke_entry_count": public_archive_reproduction_smoke.get("entry_count"),
        "public_archive_reproduction_smoke_extracted_file_count": public_archive_reproduction_smoke.get("extracted_file_count"),
        "public_archive_reproduction_smoke_markdown_count": public_archive_reproduction_smoke.get("markdown_count"),
        "public_archive_reproduction_smoke_pptx_count": public_archive_reproduction_smoke.get("pptx_count"),
        "public_archive_reproduction_smoke_missing_required_count": public_archive_reproduction_smoke.get("missing_required_count"),
        "public_archive_reproduction_smoke_readme_missing_count": public_archive_reproduction_smoke.get("readme_missing_count"),
        "public_archive_reproduction_smoke_sha_mismatch_count": public_archive_reproduction_smoke.get("sha_mismatch_count"),
        "public_archive_reproduction_smoke_invalid_office_file_count": public_archive_reproduction_smoke.get("invalid_office_file_count"),
        "public_archive_reproduction_smoke_forbidden_entry_count": public_archive_reproduction_smoke.get("forbidden_entry_count"),
        "public_archive_reproduction_smoke_secret_hit_count": public_archive_reproduction_smoke.get("secret_hit_count"),
        "public_archive_reproduction_smoke_claim_boundary_ok": public_archive_reproduction_smoke.get("claim_boundary_ok"),
        "public_archive_reproduction_smoke_claim_boundary": public_archive_reproduction_smoke.get("claim_boundary"),
    }


def artifact_kind(path: Path, metadata: dict[str, Any] | None = None) -> str:
    name = path.name.lower()
    schema = (metadata or {}).get("schema_version")
    if name.endswith(".html"):
        return "dashboard"
    if schema in SCHEMA_KIND_MAP:
        return SCHEMA_KIND_MAP[str(schema)]
    if "real_model_gate" in name or "real-model-gate" in name:
        return "model_recommendation_gate"
    if "real-matrix" in name or "real_matrix" in name:
        return "real_model_matrix"
    if "policy_profile" in name or "policy_profiles" in name:
        return "policy_profile_comparison"
    for marker, kind in NAME_KIND_RULES:
        if marker in name:
            return kind
    return "model_matrix" if "matrix" in name or "recommended_guardx" in name else path.suffix.lstrip(".") or "artifact"
