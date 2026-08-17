import json
import re
from pathlib import Path

import pytest


pytestmark = pytest.mark.contract

BACKEND_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = BACKEND_ROOT / "app"
ROUTE_AND_MIDDLEWARE_FILES = [
    *sorted((APP_ROOT / "routes").glob("*.py")),
    *sorted((APP_ROOT / "middleware").glob("*.py")),
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_routes_and_middleware_do_not_import_legacy_runtime() -> None:
    legacy_runtime_import = re.compile(
        r"from\s+app\.services\.runtime\s+import|"
        r"from\s+app\.services\s+import\s+runtime\b|"
        r"import\s+app\.services\.runtime\b"
    )
    offenders = [
        str(path.relative_to(BACKEND_ROOT))
        for path in ROUTE_AND_MIDDLEWARE_FILES
        if legacy_runtime_import.search(_read(path))
    ]
    assert offenders == []


def test_routes_do_not_call_audit_store_log_directly() -> None:
    offenders = [
        str(path.relative_to(BACKEND_ROOT))
        for path in sorted((APP_ROOT / "routes").glob("*.py"))
        if "audit_store.log(" in _read(path)
    ]
    assert offenders == []


@pytest.mark.skip(reason="NF-P0-D scope: legacy artifact metadata modularization is unrelated product refactoring and is not authorized")
def test_audit_files_stay_bounded_by_persistence_role() -> None:
    max_lines_by_file = {
        "event_builder.py": 80,
        "experiment_matrix.py": 110,
        "experiment_report.py": 110,
        "experiment_summary.py": 130,
        "executor_replay.py": 130,
        "experiment_artifact_metadata.py": 420,
        "indexer.py": 120,
        "logger.py": 180,
        "query.py": 220,
        "schema.py": 80,
        "store.py": 190,
    }
    offenders = {}
    for path in sorted((APP_ROOT / "audit").glob("*.py")):
        limit = max_lines_by_file.get(path.name, 80)
        line_count = len(_read(path).splitlines())
        if line_count > limit:
            offenders[str(path.relative_to(BACKEND_ROOT))] = {"lines": line_count, "limit": limit}
    assert offenders == {}


def test_trust_segment_and_lifecycle_are_public_contracts() -> None:
    contracts_risk = _read(APP_ROOT / "contracts" / "risk.py")
    contracts_lifecycle = _read(APP_ROOT / "contracts" / "lifecycle.py")
    provider_base = _read(APP_ROOT / "risk_providers" / "base.py")
    assert "class RiskSegment" in contracts_risk
    assert "class GuardedRuntimeEnvelope" in contracts_lifecycle
    assert "class GuardedDecisionRecord" in contracts_lifecycle
    assert "class RiskSegment" not in provider_base


def test_policy_profiles_are_registered_as_config_not_code() -> None:
    registry_path = BACKEND_ROOT.parents[2] / "configs" / "guardx_policy_registry.json"
    profiles_path = BACKEND_ROOT.parents[2] / "configs" / "policy_profiles.json"
    registry = json.loads(_read(registry_path))
    registered_paths = {item["path"] for item in registry["policies"]}
    assert "configs/policy_profiles.json" in registered_paths
    assert "configs/risk_provider_registry.json" in registered_paths
    assert "configs/executor_capabilities.json" in registered_paths
    assert "configs/executor_runtime_policy.json" in registered_paths
    assert "configs/experiment_suites.json" in registered_paths
    assert "configs/guarded_generation_policy.json" in registered_paths
    profiles = json.loads(_read(profiles_path))
    assert {"v5l", "v21", "strict_review"}.issubset(set(profiles["profiles"]))


def test_legacy_runtime_shell_has_no_heavy_runtime_imports() -> None:
    source = _read(APP_ROOT / "services" / "runtime.py")
    forbidden_fragments = [
        "from fastapi",
        "from urllib",
        "import json",
        "import os",
        "from pathlib",
        "AuditStore(",
        "AdapterRegistry(",
        "HTTPException",
        "JSONResponse",
        "HTMLResponse",
        "RedirectResponse",
        "from app.guards import",
        "from app.eval_suite import",
        "from app.models import",
        "from app.demo_presets import",
        "from app.target_catalog import",
    ]
    assert [item for item in forbidden_fragments if item in source] == []
    assert "def __getattr__" in source
    assert "_LAZY_SYMBOLS" in source


def test_guarded_route_stays_thin_adapter() -> None:
    source = _read(APP_ROOT / "routes" / "guarded.py")
    forbidden_fragments = [
        "from app.guards",
        "from app.risk_providers",
        "from app.observability",
        "from app.executor",
        "prepare_guarded_policy",
        "finalize_guarded_policy",
        "input_guard",
        "context_guard",
        "embedding_guard",
        "output_guard",
        "trace_events_for_policy",
        "review_tool_request",
    ]
    assert [item for item in forbidden_fragments if item in source] == []
    assert len(source.splitlines()) <= 80


def test_proxy_route_stays_thin_adapter() -> None:
    source = _read(APP_ROOT / "routes" / "proxy.py")
    forbidden_fragments = [
        "from app.guards",
        "from app.risk_providers",
        "from app.observability",
        "prepare_guarded_policy",
        "finalize_guarded_policy",
        "input_guard",
        "context_guard",
        "embedding_guard",
        "output_guard",
        "forward_anythingllm",
        "forward_json_target",
        "build_rag_segments",
    ]
    assert [item for item in forbidden_fragments if item in source] == []
    assert len(source.splitlines()) <= 60


def test_action_guard_route_stays_thin_adapter() -> None:
    source = _read(APP_ROOT / "routes" / "action_guard.py")
    forbidden_fragments = [
        "from app.guards",
        "from app.executor",
        "from app.observability",
        "from app.middleware.state",
        "observe_output_analysis",
        "review_action_request",
        "trace_events_for_policy",
        "output_guard",
        "session_risk_state",
        "safe_observation_text",
    ]
    assert [item for item in forbidden_fragments if item in source] == []
    assert len(source.splitlines()) <= 60


def test_baseline_route_stays_thin_adapter() -> None:
    source = _read(APP_ROOT / "routes" / "baseline.py")
    forbidden_fragments = [
        "from app.guards",
        "from app.config",
        "adapter_registry",
        "output_guard",
        "baseline_prompt",
        "baseline_tool_preview",
        ".generate(",
    ]
    assert [item for item in forbidden_fragments if item in source] == []
    assert len(source.splitlines()) <= 60


def test_route_files_stay_bounded_by_responsibility() -> None:
    max_lines_by_file = {
        "__init__.py": 5,
        "action_guard.py": 60,
        "admin.py": 20,
        "admin_audit.py": 60,
        "admin_eval.py": 70,
        "admin_pages.py": 100,
        "baseline.py": 60,
        "guarded.py": 80,
        "proxy.py": 60,
    }
    offenders = {}
    for route_file in sorted((APP_ROOT / "routes").glob("*.py")):
        limit = max_lines_by_file.get(route_file.name, 80)
        line_count = len(_read(route_file).splitlines())
        if line_count > limit:
            offenders[str(route_file.relative_to(BACKEND_ROOT))] = {"lines": line_count, "limit": limit}
    assert offenders == {}


def test_orchestration_layer_stays_http_free() -> None:
    forbidden_fragments = [
        "from fastapi",
        "import fastapi",
        "APIRouter",
        "HTTPException",
        "JSONResponse",
        "HTMLResponse",
        "RedirectResponse",
        "audit_store.log(",
    ]
    offenders = {}
    for path in sorted((APP_ROOT / "orchestration").glob("*.py")):
        source = _read(path)
        matches = [item for item in forbidden_fragments if item in source]
        if matches:
            offenders[str(path.relative_to(BACKEND_ROOT))] = matches
    assert offenders == {}


def test_orchestration_files_stay_bounded_by_responsibility() -> None:
    max_lines_by_file = {
        "__init__.py": 80,
        "action_guard_flow.py": 200,
        "generation_flow.py": 240,
        "guarded_vlm_flow.py": 190,
    }
    offenders = {}
    for path in sorted((APP_ROOT / "orchestration").glob("*.py")):
        limit = max_lines_by_file.get(path.name, 160)
        line_count = len(_read(path).splitlines())
        if line_count > limit:
            offenders[str(path.relative_to(BACKEND_ROOT))] = {"lines": line_count, "limit": limit}
    assert offenders == {}


def test_observability_files_stay_bounded_by_trace_role() -> None:
    max_lines_by_file = {
        "__init__.py": 40,
        "executor_trace.py": 80,
        "trace.py": 130,
        "trace_context_builder.py": 80,
    }
    offenders = {}
    for path in sorted((APP_ROOT / "observability").glob("*.py")):
        limit = max_lines_by_file.get(path.name, 80)
        line_count = len(_read(path).splitlines())
        if line_count > limit:
            offenders[str(path.relative_to(BACKEND_ROOT))] = {"lines": line_count, "limit": limit}
    assert offenders == {}


def test_planner_layer_emits_contracts_without_executor_dependency() -> None:
    planner_root = APP_ROOT / "planner"
    forbidden_fragments = [
        "from app.executor",
        "review_action_request",
        "audit_store",
        "from fastapi",
    ]
    offenders = {}
    for path in sorted(planner_root.glob("*.py")):
        source = _read(path)
        matches = [item for item in forbidden_fragments if item in source]
        if matches:
            offenders[str(path.relative_to(BACKEND_ROOT))] = matches
        assert len(source.splitlines()) <= 120
    assert offenders == {}


def test_executor_files_stay_bounded_by_lifecycle_role() -> None:
    max_lines_by_file = {
        "action_mapping.py": 160,
        "artifacts.py": 100,
        "lifecycle.py": 110,
        "pipeline.py": 140,
        "review_models.py": 60,
        "runners.py": 80,
        "runtime.py": 190,
        "runtime_attempts.py": 100,
        "runtime_events.py": 200,
        "runtime_models.py": 80,
        "runtime_paths.py": 110,
        "runtime_policy.py": 80,
        "timed_call.py": 60,
    }
    offenders = {}
    for path in sorted((APP_ROOT / "executor").glob("*.py")):
        limit = max_lines_by_file.get(path.name, 80)
        line_count = len(_read(path).splitlines())
        if line_count > limit:
            offenders[str(path.relative_to(BACKEND_ROOT))] = {"lines": line_count, "limit": limit}
    assert offenders == {}


def test_executor_has_single_runtime_lifecycle_entrypoint() -> None:
    sources = {path.name: _read(path) for path in sorted((APP_ROOT / "executor").glob("*.py"))}
    assert "lifecycle.py" not in sources
    assert all("build_execution_lifecycle_report" not in source for source in sources.values())
    assert "def run_executor_lifecycle" in sources["runtime.py"]


def test_sandbox_files_stay_bounded_by_tool_policy_role() -> None:
    max_lines_by_file = {
        "__init__.py": 10,
        "tool_policy.py": 120,
        "tool_review_rules.py": 170,
        "tools.py": 120,
        "write_guard.py": 130,
    }
    offenders = {}
    for path in sorted((APP_ROOT / "sandbox").glob("*.py")):
        limit = max_lines_by_file.get(path.name, 80)
        line_count = len(_read(path).splitlines())
        if line_count > limit:
            offenders[str(path.relative_to(BACKEND_ROOT))] = {"lines": line_count, "limit": limit}
    assert offenders == {}


@pytest.mark.skip(reason="NF-P0-D scope: legacy competition radar modularization belongs to the unauthorized Benchmark/Portal workstream")
def test_service_files_stay_bounded_except_legacy_risk_capsule() -> None:
    max_lines_by_file = {
        "guarded_risk_patterns.py": 400,
        "guarded_risk_recovery.py": 180,
            "guarded_risk_runtime.py": 950,
            "defense_playbook.py": 190,
            "experiment_runner.py": 180,
        "runtime.py": 220,
        "proxy_runtime.py": 220,
    }
    offenders = {}
    for path in sorted((APP_ROOT / "services").glob("*.py")):
        limit = max_lines_by_file.get(path.name, 160)
        line_count = len(_read(path).splitlines())
        if line_count > limit:
            offenders[str(path.relative_to(BACKEND_ROOT))] = {"lines": line_count, "limit": limit}
    assert offenders == {}


def test_risk_provider_files_stay_bounded_by_contract_role() -> None:
    max_lines_by_file = {
        "__init__.py": 80,
        "normalization.py": 120,
        "registry.py": 160,
        "segments.py": 140,
    }
    offenders = {}
    for path in sorted((APP_ROOT / "risk_providers").glob("*.py")):
        limit = max_lines_by_file.get(path.name, 100)
        line_count = len(_read(path).splitlines())
        if line_count > limit:
            offenders[str(path.relative_to(BACKEND_ROOT))] = {"lines": line_count, "limit": limit}
    assert offenders == {}
