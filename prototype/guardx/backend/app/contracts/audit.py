from typing import Any, Literal

from pydantic import BaseModel, Field


class ExperimentRunQuality(BaseModel):
    run_fingerprint: str = Field(min_length=16, max_length=16)
    comparison_ready: bool = False
    coverage: dict[str, int] = Field(default_factory=dict)
    missing: dict[str, int] = Field(default_factory=dict)


class ExperimentRunSummary(BaseModel):
    schema_version: Literal["guardx-experiment-run-summary-v1"] = "guardx-experiment-run-summary-v1"
    total_decision_records: int = Field(default=0, ge=0)
    run_quality: ExperimentRunQuality
    experiment_dimensions: dict[str, dict[str, int]] = Field(default_factory=dict)
    comparison_matrix: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    policy_profiles: dict[str, Any] = Field(default_factory=dict)
    risk_providers: dict[str, Any] = Field(default_factory=dict)
    executor_policy_summary: dict[str, Any] = Field(default_factory=dict)


class ExperimentSummaryFilters(BaseModel):
    suite_id: str | None = None
    case_id: str | None = None
    policy_profile: str | None = None


class ExperimentSummaryResponse(BaseModel):
    session_id: str | None = None
    trace_id: str | None = None
    filters: ExperimentSummaryFilters = Field(default_factory=ExperimentSummaryFilters)
    summary: ExperimentRunSummary


class ExperimentReportResponse(BaseModel):
    schema_version: Literal["guardx-experiment-report-v1"] = "guardx-experiment-report-v1"
    scope: dict[str, Any] = Field(default_factory=dict)
    run_fingerprint: str = Field(min_length=16, max_length=16)
    comparison_ready: bool = False
    key_metrics: dict[str, Any] = Field(default_factory=dict)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    recommended_next_actions: list[str] = Field(default_factory=list)
    markdown: str = ""


class ExperimentSuiteRunResponse(BaseModel):
    schema_version: Literal["guardx-experiment-suite-run-v1"] = "guardx-experiment-suite-run-v1"
    suite_id: str
    session_id: str
    policy_profile: str
    model: str
    cases: list[dict[str, Any]] = Field(default_factory=list)
    report: ExperimentReportResponse


class ExperimentModelMatrixResponse(BaseModel):
    schema_version: Literal["guardx-experiment-model-matrix-v1"] = "guardx-experiment-model-matrix-v1"
    suite_id: str
    policy_profile: str
    base_session_id: str
    models: list[str] = Field(default_factory=list)
    runs: list[ExperimentSuiteRunResponse] = Field(default_factory=list)
    comparison: list[dict[str, Any]] = Field(default_factory=list)


class ExperimentStabilityResponse(BaseModel):
    schema_version: Literal["guardx-experiment-stability-v1"] = "guardx-experiment-stability-v1"
    run_id: str
    suite_id: str
    policy_profile: str
    rounds: int = Field(ge=1)
    models: list[str] = Field(default_factory=list)
    round_artifacts: list[str] = Field(default_factory=list)
    model_summaries: dict[str, dict[str, Any]] = Field(default_factory=dict)
    case_summaries: dict[str, dict[str, Any]] = Field(default_factory=dict)
    stable_models: list[str] = Field(default_factory=list)
    unstable_models: list[str] = Field(default_factory=list)
    key_findings: list[str] = Field(default_factory=list)


class ModelOutputHealthProbe(BaseModel):
    probe_id: str
    message: str
    surface: str = "chat"


class ModelOutputHealthResult(BaseModel):
    model: str
    probe_id: str
    configured: bool
    status: Literal["ok", "empty", "no_final", "unavailable", "error"]
    latency_ms: float = Field(default=0.0, ge=0.0)
    content_length: int = Field(default=0, ge=0)
    output_preview: str = ""
    error_type: str | None = None
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ModelOutputHealthResponse(BaseModel):
    schema_version: Literal["guardx-model-output-health-v1"] = "guardx-model-output-health-v1"
    run_id: str
    models: list[str] = Field(default_factory=list)
    probes: list[ModelOutputHealthProbe] = Field(default_factory=list)
    results: list[ModelOutputHealthResult] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


class ExperimentSuiteCase(BaseModel):
    case_id: str
    kind: Literal["chat", "rag", "vlm_ocr", "action", "observation"]
    expectation: Literal["benign", "attack", "mixed"] = "mixed"
    expected_routes: list[Literal["allow", "review", "block"]] = Field(default_factory=list)
    story_stage: str = ""
    demo_claim: str = ""
    attack_vector: str = ""
    trust_boundary: str = ""
    benchmark_family: str = ""
    benchmark_task: str = ""
    security_property: str = ""
    message: str = ""
    history: list[dict[str, str]] = Field(default_factory=list)
    context: str = ""
    image_id: str = "local-image"
    ocr_text: str = ""
    vlm_answer: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    ocr_engine: str = ""
    ocr_engine_version: str = ""
    ocr_output_path: str = ""
    ocr_output_sha256: str = ""
    rendered_image_sha256: str = ""
    ocr_manifest_path: str = ""
    ocr_disagreement: dict[str, Any] = Field(default_factory=dict)
    surface: str = "agent_tool"
    action: dict[str, Any] = Field(default_factory=dict)
    observation: str = ""
    risk_hint: float | None = None


class ExperimentSuiteDefinition(BaseModel):
    cases: list[ExperimentSuiteCase] = Field(default_factory=list)
    isolate_cases: bool = False


class ExperimentSuiteManifest(BaseModel):
    schema_version: Literal["guardx-experiment-suites-v1"] = "guardx-experiment-suites-v1"
    default_suite: str = "guardx_builtin_smoke"
    suites: dict[str, ExperimentSuiteDefinition] = Field(default_factory=dict)
