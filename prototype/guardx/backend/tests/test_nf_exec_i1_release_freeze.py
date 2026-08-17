import json
from pathlib import Path

from app.contracts.executor_integration import (
    APPROVAL_CONTRACT_VERSION,
    CORE_V2_COMPATIBILITY_VERSION,
    EXECUTOR_CONTRACT_VERSION,
)
from app.integration.executor_service import FROZEN_EXECUTOR_COMMIT


ROOT = Path(__file__).resolve().parents[6]
EVIDENCE = ROOT / "04_evidence/nf_exec_i1_contract_freeze"


def test_frozen_versions_and_executor_parent_are_exact() -> None:
    assert EXECUTOR_CONTRACT_VERSION == "guardx-executor-service-v1"
    assert APPROVAL_CONTRACT_VERSION == "guardx-approval-integration-v1"
    assert CORE_V2_COMPATIBILITY_VERSION == "guardx-core-v2-executor-map-v1"
    assert FROZEN_EXECUTOR_COMMIT == "58f8cba93d7b632a46687ce81160f604a5cfa378"


def test_release_evidence_is_complete_and_contains_no_secret() -> None:
    expected = {
        "api_service_schema.json",
        "approval_service.schema.json",
        "compatibility_matrix.json",
        "dependency_note.json",
        "executor_service.schema.json",
        "freeze_manifest.json",
        "security_invariants.json",
    }
    assert {path.name for path in EVIDENCE.iterdir()} == expected
    manifest = json.loads((EVIDENCE / "freeze_manifest.json").read_text(encoding="utf-8"))
    assert manifest["verdict"] == "PASS_EXECUTOR_INTEGRATION_CONTRACT_FROZEN"
    assert manifest["runner_count_added"] == 0
    assert manifest["core_executor_semantics_changed"] is False
    assert manifest["production_secret_in_repository"] is False
    combined = "\n".join(path.read_text(encoding="utf-8") for path in EVIDENCE.iterdir())
    assert "nf-exec-i1-test-secret" not in combined
    assert "signature\"" not in (EVIDENCE / "api_service_schema.json").read_text(encoding="utf-8")
