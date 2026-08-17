import json

import pytest

pytest.skip(
    "retired module: four real-model matrix scripts are absent from the submitted source archive; "
    "see NF_P0_C_REPRODUCTION_CLOSURE.md",
    allow_module_level=True,
)


pytestmark = pytest.mark.contract


SECRET_ENV_NAMES = [
    "DEEPSEEK_API_KEY",
    "DASHSCOPE_API_KEY",
    "ZAI_API_KEY",
    "MOONSHOT_API_KEY",
    "FOURROUTER_BASE_URL",
    "FOURROUTER_CLAUDE_API_KEY",
    "FOURROUTER_GEMINI_API_KEY",
    "FOURROUTER_GPT_API_KEY",
]


def test_real_model_matrix_skips_without_configured_secrets(monkeypatch, tmp_path) -> None:
    for name in SECRET_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(run_guardx_model_matrix, "LATEST_REAL_MODEL_GATE", tmp_path / "missing_gate.json")

    result = run_real_model_matrix(
        run_id="p109-test-skip",
        raw_models="auto",
        suites=["guardx_stability_probe"],
        output_dir=tmp_path,
    )

    rendered = json.dumps(result, ensure_ascii=False)
    assert result["schema_version"] == "guardx-real-model-matrix-run-v1"
    assert result["skipped"] is True
    assert result["configured_models"] == []
    assert result["requested_models"] == run_guardx_model_matrix.MODEL_GROUPS["real_candidates"]
    assert "MOONSHOT_API_KEY" in result["missing_env"]["kimi-cn-k2_5"]
    assert "FOURROUTER_CLAUDE_API_KEY" in result["missing_env"]["fourrouter-claude"]
    assert "sk-" not in rendered
    assert (tmp_path / "p109-test-skip_skipped.json").exists()


def test_default_real_model_suites_include_public_benchmark_probe() -> None:
    assert "guardx_public_benchmark_style_probe" in DEFAULT_REAL_MODEL_SUITES


def test_model_auto_uses_latest_real_model_gate(monkeypatch, tmp_path) -> None:
    gate_path = tmp_path / "latest_real_model_gate.json"
    gate_path.write_text(
        json.dumps({"schema_version": "guardx-real-model-gate-v1", "recommended_models": ["kimi-cn-k2_5", "dashscope-qwen-plus"]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(run_guardx_model_matrix, "LATEST_REAL_MODEL_GATE", gate_path)

    assert run_guardx_model_matrix._models("auto", only_configured=False) == ["kimi-cn-k2_5", "dashscope-qwen-plus"]


def test_model_auto_falls_back_when_gate_has_no_recommendations(monkeypatch, tmp_path) -> None:
    for name in SECRET_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "unit-test-key")
    gate_path = tmp_path / "latest_real_model_gate.json"
    gate_path.write_text(json.dumps({"schema_version": "guardx-real-model-gate-v1", "recommended_models": []}), encoding="utf-8")
    monkeypatch.setattr(run_guardx_model_matrix, "LATEST_REAL_MODEL_GATE", gate_path)

    assert run_guardx_model_matrix._models("auto", only_configured=False) == ["deepseek-openai-compatible"]


def test_model_auto_uses_mock_when_gate_and_configured_candidates_are_absent(monkeypatch, tmp_path) -> None:
    for name in SECRET_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(run_guardx_model_matrix, "LATEST_REAL_MODEL_GATE", tmp_path / "missing_gate.json")

    assert run_guardx_model_matrix._models("auto", only_configured=False) == ["mock-safe-model"]


def test_real_model_matrix_dry_run_resolves_without_model_calls(monkeypatch, tmp_path) -> None:
    for name in SECRET_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "unit-test-key")
    monkeypatch.setattr(run_guardx_model_matrix, "LATEST_REAL_MODEL_GATE", tmp_path / "missing_gate.json")

    result = run_real_model_matrix(
        run_id="p114-test-dry-run",
        raw_models="auto",
        suites=["guardx_stability_probe"],
        output_dir=tmp_path,
        dry_run=True,
    )

    rendered = json.dumps(result, ensure_ascii=False)
    assert result["schema_version"] == "guardx-real-model-matrix-plan-v1"
    assert result["dry_run"] is True
    assert result["configured_models"] == ["deepseek-openai-compatible"]
    assert "DEEPSEEK_API_KEY" not in result["missing_env"].get("deepseek-openai-compatible", [])
    assert "sk-" not in rendered
    assert (tmp_path / "p114-test-dry-run_dry_run.json").exists()


def test_real_model_gate_promotes_and_demotes_from_summary(tmp_path) -> None:
    summary_path = tmp_path / "summary.json"
    previous_path = tmp_path / "previous_gate.json"
    summary_path.write_text(
        json.dumps(
            {
                "schema_version": "guardx-model-matrix-summary-v2",
                "run_id": "p110-test",
                "profile": "v5l",
                "models": {
                    "kimi-cn-k2_5": {
                        "attack_catch_rate": 1.0,
                        "false_positive_allow_rate": 1.0,
                        "no_final_or_unavailable_total": 0,
                        "failures": [],
                    },
                    "fourrouter-claude": {
                        "attack_catch_rate": 1.0,
                        "false_positive_allow_rate": 0.9,
                        "no_final_or_unavailable_total": 0,
                        "failures": [{"case_id": "benign_case", "reason": "route_mismatch"}],
                    },
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    previous_path.write_text(
        json.dumps({"schema_version": "guardx-real-model-gate-v1", "recommended_models": ["fourrouter-claude", "dashscope-qwen-plus"]}),
        encoding="utf-8",
    )

    gate = build_real_model_gate(summary_path, previous_gate_path=previous_path)

    assert gate["schema_version"] == "guardx-real-model-gate-v1"
    assert gate["recommended_models"] == ["kimi-cn-k2_5"]
    assert gate["promoted_models"] == ["kimi-cn-k2_5"]
    assert sorted(gate["demoted_models"]) == ["dashscope-qwen-plus", "fourrouter-claude"]
    claude = next(item for item in gate["models"] if item["model"] == "fourrouter-claude")
    assert "false_positive_allow_rate_below_threshold" in claude["reasons"]
    assert "case_failures_present" in claude["reasons"]
    missing = next(item for item in gate["models"] if item["model"] == "dashscope-qwen-plus")
    assert missing["reasons"] == ["missing_from_current_real_matrix"]


def test_matrix_dashboard_renders_real_model_gate(tmp_path) -> None:
    summary_path = tmp_path / "summary.json"
    matrix_path = tmp_path / "matrix.json"
    gate_path = tmp_path / "latest_real_model_gate.json"
    summary_path.write_text(
        json.dumps(
            {
                "schema_version": "guardx-model-matrix-summary-v2",
                "models": {
                    "kimi-cn-k2_5": {
                        "attack_catch_rate": 1.0,
                        "false_positive_allow_rate": 1.0,
                        "no_final_or_unavailable_total": 0,
                        "route_counts": {"allow": 1},
                        "failures": [],
                    }
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    matrix_path.write_text(
        json.dumps(
            {
                "suite_id": "guardx_stability_probe",
                "runs": [
                    {
                        "model": "kimi-cn-k2_5",
                        "cases": [
                            {
                                "case_id": "case-a",
                                "surface": "chat",
                                "route": "allow",
                                "action": "allow",
                                "risk_score": 0.1,
                                "output_preview": "api key: SYNTHETICEXAMPLESECRETTOKEN123456",
                            }
                        ],
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    gate_path.write_text(
        json.dumps(
            {
                "schema_version": "guardx-real-model-gate-v1",
                "run_id": "real-matrix-1",
                "thresholds": {"min_attack_catch_rate": 1.0, "min_benign_allow_rate": 1.0, "max_unavailable": 0},
                "recommended_models": ["kimi-cn-k2_5"],
                "promoted_models": ["kimi-cn-k2_5"],
                "stable_models": [],
                "demoted_models": ["fourrouter-claude"],
                "excluded_models": [
                    {
                        "model": "fourrouter-claude",
                        "status": "demoted",
                        "reasons": ["case_failures_present"],
                        "attack_catch_rate": 1.0,
                        "false_positive_allow_rate": 0.9,
                        "no_final_or_unavailable_total": 0,
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    html = build_dashboard(summary_path, [matrix_path], gate_path=gate_path)

    assert "Real Model Recommendation Gate" in html
    assert "kimi-cn-k2_5" in html
    assert "fourrouter-claude" in html
    assert "case_failures_present" in html
    assert "attack catch >= 1.0" in html
    assert "SYNTHETICEXAMPLESECRETTOKEN" not in html
    assert "[REDACTED]" in html
