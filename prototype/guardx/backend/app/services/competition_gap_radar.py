from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.services import experiment_artifact_index


PROJECT_ROOT = Path(__file__).resolve().parents[5]
BACKEND_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = PROJECT_ROOT / "configs" / "competition_gap_profiles.json"
SCHEMA_VERSION = "guardx-competition-gap-radar-v1"


def _load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {
            "schema_version": "guardx-competition-gap-profiles-v1",
            "minimum_score": 0.75,
            "winner_baselines": [],
            "capabilities": [],
        }


def _latest_by_kind() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in experiment_artifact_index.list_experiment_artifacts(limit=1000).get("artifacts", []):
        kind = str(item.get("kind") or "")
        if kind and kind not in result:
            result[kind] = item
    return result


def _file_exists(name: str) -> bool:
    candidates = [BACKEND_ROOT / name, PROJECT_ROOT / name]
    return any(path.exists() for path in candidates)


def _as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _artifact_ready(kind: str, artifacts: dict[str, dict[str, Any]]) -> tuple[bool, str]:
    item = artifacts.get(kind)
    if not item:
        return False, "missing_artifact"
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    if kind == "model_recommendation_gate" and not metadata.get("recommended_models"):
        return False, "no_recommended_models"
    if kind == "live_target_preflight":
        return (metadata.get("blocker_count") is not None), item.get("name") or "available"
    if kind == "target_integration_replay" and metadata.get("passed") is False:
        return False, "target_replay_failed"
    if kind == "final_submission_gate":
        if metadata.get("final_gate_status") != "pass" or int(metadata.get("final_gate_failed_count") or 0) != 0:
            return False, "final_gate_failed"
        if int(metadata.get("final_gate_check_count") or 0) < 120:
            return False, "final_gate_check_count_below_120"
    if kind == "demo_flow_summary":
        if metadata.get("demo_flow_summary_ready") is not True:
            return False, "demo_flow_summary_not_ready"
        if int(metadata.get("final_demo_story_count") or 0) != 4:
            return False, "final_demo_story_count_not_4"
        if metadata.get("final_demo_raw_prompt_rendered") is not False:
            return False, "final_demo_raw_prompt_boundary_failed"
        if metadata.get("final_demo_real_private_data_rendered") is not False:
            return False, "final_demo_private_data_boundary_failed"
    if kind == "submission_package_manifest":
        if metadata.get("submission_package_status") != "pass":
            return False, "submission_package_failed"
        if int(metadata.get("submission_package_forbidden_count") or 0) != 0:
            return False, "forbidden_files_tracked"
        if int(metadata.get("submission_package_secret_hit_count") or 0) != 0:
            return False, "secret_hits_detected"
    if kind == "claim_defense_matrix":
        if metadata.get("claim_defense_ready") is not True:
            return False, "claim_defense_not_ready"
        if int(metadata.get("claim_defense_item_count") or 0) < 8:
            return False, "claim_defense_items_below_8"
        if int(metadata.get("claim_defense_unresolved_count") or 0) != 0:
            return False, "claim_defense_has_unresolved"
        if metadata.get("claim_defense_raw_prompt_rendered") is not False:
            return False, "claim_defense_raw_prompt_boundary_failed"
        if metadata.get("claim_defense_real_private_data_rendered") is not False:
            return False, "claim_defense_private_data_boundary_failed"
    if kind == "final_rehearsal_runbook":
        if metadata.get("final_rehearsal_ready") is not True:
            return False, "final_rehearsal_not_ready"
        if int(metadata.get("final_rehearsal_command_count") or 0) < 5:
            return False, "final_rehearsal_commands_below_5"
        if int(metadata.get("final_rehearsal_pitch_count") or 0) < 7:
            return False, "final_rehearsal_pitch_below_7"
        if int(metadata.get("final_rehearsal_pitch_total_seconds") or 0) > 600:
            return False, "final_rehearsal_pitch_too_long"
        if int(metadata.get("final_rehearsal_flow_count") or 0) != 4:
            return False, "final_rehearsal_flow_not_4"
        if int(metadata.get("final_rehearsal_qna_count") or 0) < 8:
            return False, "final_rehearsal_qna_below_8"
        if metadata.get("final_rehearsal_raw_prompt_rendered") is not False:
            return False, "final_rehearsal_raw_prompt_boundary_failed"
        if metadata.get("final_rehearsal_real_private_data_rendered") is not False:
            return False, "final_rehearsal_private_data_boundary_failed"
    if kind == "official_submission_handoff_checklist":
        if metadata.get("official_submission_handoff_ready") is not True:
            return False, "official_handoff_not_ready"
        if int(metadata.get("official_submission_handoff_manual_count") or 0) < 10:
            return False, "official_handoff_manual_items_below_10"
        if int(metadata.get("official_submission_handoff_manual_pending_count") or 0) < 1:
            return False, "official_handoff_missing_manual_pending_boundary"
        if int(metadata.get("official_submission_handoff_source_count") or 0) < 5:
            return False, "official_handoff_sources_below_5"
        if metadata.get("official_submission_handoff_claimed") is not False:
            return False, "official_handoff_claim_boundary_failed"
        if metadata.get("official_submission_handoff_raw_prompt_rendered") is not False:
            return False, "official_handoff_raw_prompt_boundary_failed"
        if metadata.get("official_submission_handoff_real_private_data_rendered") is not False:
            return False, "official_handoff_private_data_boundary_failed"
    if kind == "demo_recording_plan":
        if metadata.get("final_demo_video_ready") is not True:
            return False, "final_demo_video_not_ready"
        if int(metadata.get("final_demo_video_shot_count") or 0) < 8:
            return False, "final_demo_video_shots_below_8"
        if int(metadata.get("final_demo_video_target_seconds") or 0) > 660:
            return False, "final_demo_video_too_long"
        if int(metadata.get("final_demo_video_recording_check_count") or 0) < 5:
            return False, "final_demo_video_recording_checks_below_5"
        if int(metadata.get("final_demo_video_portal_cards_available") or 0) < 13:
            return False, "final_demo_video_portal_cards_below_13"
        if metadata.get("final_demo_video_raw_prompt_rendered") is not False:
            return False, "final_demo_video_raw_prompt_boundary_failed"
        if metadata.get("final_demo_video_real_private_data_rendered") is not False:
            return False, "final_demo_video_private_data_boundary_failed"
        if metadata.get("final_demo_video_official_submission_claimed") is not False:
            return False, "final_demo_video_claim_boundary_failed"
    if kind == "final_submission_packet_cover":
        if metadata.get("final_packet_cover_ready") is not True:
            return False, "final_packet_cover_not_ready"
        if int(metadata.get("final_packet_cover_upload_item_count") or 0) < 10:
            return False, "final_packet_cover_upload_items_below_10"
        if int(metadata.get("final_packet_cover_manual_after_upload_count") or 0) < 4:
            return False, "final_packet_cover_manual_after_upload_below_4"
        if not metadata.get("final_packet_cover_git_commit"):
            return False, "final_packet_cover_missing_commit"
        if metadata.get("final_packet_cover_raw_prompt_rendered") is not False:
            return False, "final_packet_cover_raw_prompt_boundary_failed"
        if metadata.get("final_packet_cover_real_private_data_rendered") is not False:
            return False, "final_packet_cover_private_data_boundary_failed"
        if metadata.get("final_packet_cover_official_submission_claimed") is not False:
            return False, "final_packet_cover_submission_claim_boundary_failed"
        if metadata.get("final_packet_cover_official_leaderboard_score") is not False:
            return False, "final_packet_cover_leaderboard_claim_boundary_failed"
        if metadata.get("final_packet_cover_award_claimed") is not False:
            return False, "final_packet_cover_award_claim_boundary_failed"
    if kind == "judge_rubric_scorecard":
        if metadata.get("judge_rubric_ready") is not True:
            return False, "judge_rubric_not_ready"
        if int(metadata.get("judge_rubric_local_evidence_score") or 0) < 85:
            return False, "judge_rubric_score_below_85"
        if int(metadata.get("judge_rubric_dimension_count") or 0) < 7:
            return False, "judge_rubric_dimensions_below_7"
        if metadata.get("judge_rubric_failed_dimensions"):
            return False, "judge_rubric_has_failed_dimensions"
        if int(metadata.get("judge_rubric_non_claim_count") or 0) < 4:
            return False, "judge_rubric_non_claims_below_4"
        if metadata.get("judge_rubric_raw_prompt_rendered") is not False:
            return False, "judge_rubric_raw_prompt_boundary_failed"
        if metadata.get("judge_rubric_real_private_data_rendered") is not False:
            return False, "judge_rubric_private_data_boundary_failed"
        if metadata.get("judge_rubric_official_leaderboard_score") is not False:
            return False, "judge_rubric_leaderboard_claim_boundary_failed"
        if metadata.get("judge_rubric_award_claimed") is not False:
            return False, "judge_rubric_award_claim_boundary_failed"
    if kind == "benchmark_traceability_matrix":
        if metadata.get("benchmark_traceability_ready") is not True:
            return False, "benchmark_traceability_not_ready"
        if int(metadata.get("benchmark_traceability_row_count") or 0) < 7:
            return False, "benchmark_traceability_rows_below_7"
        if int(metadata.get("benchmark_traceability_method_count") or 0) < 10:
            return False, "benchmark_traceability_methods_below_10"
        if int(metadata.get("benchmark_traceability_missing_evidence_count") or 0) != 0:
            return False, "benchmark_traceability_missing_evidence"
        if metadata.get("benchmark_traceability_same_batch_or_boundary_explained") is not True:
            return False, "benchmark_traceability_boundary_not_explained"
        if metadata.get("benchmark_traceability_raw_prompt_rendered") is not False:
            return False, "benchmark_traceability_raw_prompt_boundary_failed"
        if metadata.get("benchmark_traceability_real_private_data_rendered") is not False:
            return False, "benchmark_traceability_private_data_boundary_failed"
        if metadata.get("benchmark_traceability_official_leaderboard_score") is not False:
            return False, "benchmark_traceability_leaderboard_claim_boundary_failed"
    if kind == "final_live_demo_rehearsal_scorecard":
        if metadata.get("final_live_demo_scorecard_ready") is not True:
            return False, "final_live_demo_scorecard_not_ready"
        if int(metadata.get("final_live_demo_scorecard_check_count") or 0) < 18:
            return False, "final_live_demo_scorecard_checks_below_18"
        if int(metadata.get("final_live_demo_scorecard_failed_count") or 0) != 0:
            return False, "final_live_demo_scorecard_has_failures"
        if int(metadata.get("final_live_demo_scorecard_story_count") or 0) != 4:
            return False, "final_live_demo_scorecard_story_count_not_4"
        if int(metadata.get("final_live_demo_scorecard_portal_story_card_count") or 0) != 4:
            return False, "final_live_demo_scorecard_portal_story_cards_not_4"
        if int(metadata.get("final_live_demo_scorecard_shot_count") or 0) < 8:
            return False, "final_live_demo_scorecard_shots_below_8"
        if int(metadata.get("final_live_demo_scorecard_pitch_total_seconds") or 0) > 600:
            return False, "final_live_demo_scorecard_pitch_too_long"
        if int(metadata.get("final_live_demo_scorecard_qna_count") or 0) < 8:
            return False, "final_live_demo_scorecard_qna_below_8"
        if int(metadata.get("final_live_demo_scorecard_recording_check_count") or 0) < 5:
            return False, "final_live_demo_scorecard_recording_checks_below_5"
        if metadata.get("final_live_demo_scorecard_raw_prompt_rendered") is not False:
            return False, "final_live_demo_scorecard_raw_prompt_boundary_failed"
        if metadata.get("final_live_demo_scorecard_real_private_data_rendered") is not False:
            return False, "final_live_demo_scorecard_private_data_boundary_failed"
        if metadata.get("final_live_demo_scorecard_official_submission_claimed") is not False:
            return False, "final_live_demo_scorecard_submission_claim_boundary_failed"
        if metadata.get("final_live_demo_scorecard_official_leaderboard_score") is not False:
            return False, "final_live_demo_scorecard_leaderboard_claim_boundary_failed"
    if kind == "evidence_readiness_board":
        if metadata.get("evidence_readiness_ready") is not True:
            return False, "evidence_readiness_not_ready"
        if int(metadata.get("evidence_readiness_score") or 0) < 95:
            return False, "evidence_readiness_score_below_95"
        if int(metadata.get("evidence_readiness_dimension_count") or 0) < 7:
            return False, "evidence_readiness_dimensions_below_7"
        if int(metadata.get("evidence_readiness_passed_dimension_count") or 0) != int(metadata.get("evidence_readiness_dimension_count") or 0):
            return False, "evidence_readiness_dimensions_not_all_passed"
        if int(metadata.get("evidence_readiness_critical_open_count") or 0) != 0:
            return False, "evidence_readiness_has_critical_open"
        if metadata.get("evidence_readiness_raw_prompt_rendered") is not False:
            return False, "evidence_readiness_raw_prompt_boundary_failed"
        if metadata.get("evidence_readiness_real_private_data_rendered") is not False:
            return False, "evidence_readiness_private_data_boundary_failed"
        if metadata.get("evidence_readiness_official_submission_claimed") is not False:
            return False, "evidence_readiness_submission_claim_boundary_failed"
        if metadata.get("evidence_readiness_official_leaderboard_score") is not False:
            return False, "evidence_readiness_leaderboard_claim_boundary_failed"
        if metadata.get("evidence_readiness_award_claimed") is not False:
            return False, "evidence_readiness_award_claim_boundary_failed"
    if kind == "defense_evidence_notes":
        if metadata.get("defense_evidence_notes_ready") is not True:
            return False, "defense_evidence_notes_not_ready"
        if int(metadata.get("defense_evidence_notes_story_count") or 0) != 4:
            return False, "defense_evidence_notes_story_count_not_4"
        if int(metadata.get("defense_evidence_notes_number_count") or 0) < 6:
            return False, "defense_evidence_notes_numbers_below_6"
        if int(metadata.get("defense_evidence_notes_qna_count") or 0) < 6:
            return False, "defense_evidence_notes_qna_below_6"
        if int(metadata.get("defense_evidence_notes_do_not_say_count") or 0) < 5:
            return False, "defense_evidence_notes_do_not_say_below_5"
        if int(metadata.get("defense_evidence_notes_fallback_count") or 0) < 3:
            return False, "defense_evidence_notes_fallback_below_3"
        if metadata.get("defense_evidence_notes_raw_prompt_rendered") is not False:
            return False, "defense_evidence_notes_raw_prompt_boundary_failed"
        if metadata.get("defense_evidence_notes_real_private_data_rendered") is not False:
            return False, "defense_evidence_notes_private_data_boundary_failed"
        if metadata.get("defense_evidence_notes_official_submission_claimed") is not False:
            return False, "defense_evidence_notes_submission_claim_boundary_failed"
        if metadata.get("defense_evidence_notes_official_leaderboard_score") is not False:
            return False, "defense_evidence_notes_leaderboard_claim_boundary_failed"
        if metadata.get("defense_evidence_notes_award_claimed") is not False:
            return False, "defense_evidence_notes_award_claim_boundary_failed"
    if kind == "official_evaluator_reproducibility_ledger":
        if metadata.get("official_ledger_required_files_ok") is not True:
            return False, "ledger_required_files_not_ok"
        if metadata.get("official_ledger_no_raw_prompt_rendered") is not True:
            return False, "ledger_raw_prompt_boundary_failed"
        if metadata.get("official_ledger_leaderboard_score") is not False:
            return False, "ledger_claim_boundary_failed"
    if kind == "same_batch_unified_ablation":
        if _as_float(metadata.get("same_batch_full_attack_catch")) < 0.75:
            return False, "same_batch_attack_catch_below_0_75"
        if _as_float(metadata.get("same_batch_full_fpr")) > 0.05:
            return False, "same_batch_fpr_above_0_05"
    if kind == "agent_task_graph_replay_alignment":
        if int(metadata.get("agent_graph_alignment_case_count") or 0) < 32:
            return False, "agent_replay_case_count_below_32"
        if _as_float(metadata.get("agent_graph_alignment_security_block")) < 1.0:
            return False, "agent_security_block_below_1"
        if _as_float(metadata.get("agent_graph_alignment_benign_block")) != 0.0:
            return False, "agent_benign_block_nonzero"
    if kind == "vlm_multi_image_provider_benchmark":
        if int(metadata.get("vlm_multi_image_count") or 0) < 6:
            return False, "vlm_image_count_below_6"
        if _as_float(metadata.get("vlm_multi_provider_success_rate")) < 1.0:
            return False, "vlm_provider_success_below_1"
        if _as_float(metadata.get("vlm_multi_hard_block_fpr")) != 0.0:
            return False, "vlm_hard_block_fpr_nonzero"
    if kind == "portal_rehearsal":
        if int(metadata.get("portal_rehearsal_page_status") or 0) != 200:
            return False, "portal_page_not_200"
        if int(metadata.get("portal_rehearsal_rendered_card_count") or 0) < 14:
            return False, "portal_rendered_card_count_below_14"
        if int(metadata.get("portal_rehearsal_final_gate_checks") or 0) < 120:
            return False, "portal_final_gate_check_count_below_120"
    if kind == "harmbench_step3_importer_preflight":
        if metadata.get("harmbench_step3_importer_preflight_status") != "pass":
            return False, "harmbench_step3_importer_not_pass"
        if int(metadata.get("harmbench_step3_importer_preflight_failed_count") or 0) != 0:
            return False, "harmbench_step3_importer_failures"
    if metadata.get("skipped"):
        return False, "artifact_skipped"
    if metadata.get("parse_error"):
        return False, "artifact_parse_error"
    return True, item.get("name") or "available"


def _evaluate_capability(capability: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    required_artifacts = [str(item) for item in capability.get("required_artifact_kinds", [])]
    required_files = [str(item) for item in capability.get("required_files", [])]
    checks: list[dict[str, Any]] = []
    for kind in required_artifacts:
        passed, detail = _artifact_ready(kind, artifacts)
        checks.append({"type": "artifact", "target": kind, "passed": passed, "detail": detail})
    for filename in required_files:
        checks.append({"type": "file", "target": filename, "passed": _file_exists(filename), "detail": filename})
    passed = bool(checks) and all(item["passed"] for item in checks)
    weight = float(capability.get("weight") or 0.0)
    return {
        "id": str(capability.get("id") or "unknown"),
        "description": str(capability.get("description") or ""),
        "weight": weight,
        "passed": passed,
        "score": weight if passed else 0.0,
        "checks": checks,
        "next_action": None if passed else _next_action(capability),
    }


def _next_action(capability: dict[str, Any]) -> str:
    cid = str(capability.get("id") or "")
    actions = {
        "deployment_rehearsal": "Add Dockerfile/runbook and verify a clean startup path.",
        "continuous_learning_loop": "Create feedback-loop artifact that converts failed cases into policy/provider tasks.",
        "real_target_integration": "Run GuardX against an integrated RAG or agent target and persist replay evidence.",
        "live_target_preflight_visibility": "Run live target preflight so optional service blockers are visible before rehearsal.",
        "live_target_rehearsal": "Run local/live target rehearsal and persist profile-level evidence.",
    }
    return actions.get(cid, "Generate or refresh the required evidence artifact.")


def build_competition_gap_radar(*, run_id: str = "local-gap-radar") -> dict[str, Any]:
    config = _load_config()
    artifacts = _latest_by_kind()
    capabilities = [
        _evaluate_capability(item, artifacts)
        for item in config.get("capabilities", [])
        if isinstance(item, dict)
    ]
    total_weight = sum(float(item["weight"]) for item in capabilities) or 1.0
    score = sum(float(item["score"]) for item in capabilities) / total_weight
    gaps = [item for item in capabilities if not item["passed"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "created_at": datetime.now(UTC).isoformat(),
        "minimum_score": float(config.get("minimum_score") or 0.75),
        "score": round(score, 4),
        "ready": score >= float(config.get("minimum_score") or 0.75) and not gaps,
        "winner_baselines": config.get("winner_baselines", []),
        "capabilities": capabilities,
        "gap_count": len(gaps),
        "top_gaps": gaps[:5],
    }
