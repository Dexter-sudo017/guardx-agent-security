import json
from pathlib import Path

from app.executor_secure.integration_demo import run_integration_demo


FIXTURE = Path(__file__).parent / "fixtures" / "nf_executor_approval_demo.json"


def test_real_sandbox_executor_and_approval_runtime(tmp_path: Path) -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    evidence = tmp_path / "evidence"
    summary = run_integration_demo(base_root=tmp_path / "disposable", evidence_dir=evidence, fixture=fixture)

    assert summary["passed"] is True
    assert summary["check_count"] == 11
    assert summary["passed_count"] == 11
    assert summary["real_execution"] is True
    assert summary["dry_run"] is False
    assert summary["public_network_accessed"] is False
    assert {path.name for path in evidence.iterdir()} == {
        "summary.json",
        "filesystem_hashes.json",
        "sqlite_state_proof.json",
        "http_receiver_events.json",
        "approval_state_traces.json",
        "rollback_proof.json",
    }

    http_proof = json.loads((evidence / "http_receiver_events.json").read_text(encoding="utf-8"))
    assert http_proof["events_after_denial"] == []
    assert len(http_proof["events_after_approval"]) == 1

    traces = json.loads((evidence / "approval_state_traces.json").read_text(encoding="utf-8"))
    assert any(trace["states"] == ["RUNNING", "REQUIRE_APPROVAL", "PAUSED", "APPROVED", "RESUMED"] for trace in traces.values())
    assert any(trace["states"] == ["RUNNING", "REQUIRE_APPROVAL", "PAUSED", "REJECTED", "TERMINATED"] for trace in traces.values())
