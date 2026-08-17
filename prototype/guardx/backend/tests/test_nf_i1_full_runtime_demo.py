from pathlib import Path

from app.integration.full_runtime_demo import run_full_runtime_demo


def test_nf_i1_d01_d08_real_mini_e2e(tmp_path: Path) -> None:
    report = run_full_runtime_demo(base_root=tmp_path / "runs", evidence_dir=tmp_path / "evidence")

    assert report["passed"] is True
    assert report["case_count"] == 8
    assert report["passed_count"] == 8
    assert [item["case_id"] for item in report["cases"]] == [f"D0{index}" for index in range(1, 9)]
    assert report["public_network_accessed"] is False
    assert report["subsystem_proofs"]["sqlite"]["rows"] == [["nf-i1-sqlite-proof"]]
    assert report["subsystem_proofs"]["sqlite"]["read_preserved_state"] is True
    assert report["subsystem_proofs"]["localhost_http"]["exactly_once"] is True
    assert (tmp_path / "evidence" / "mini_e2e_report.json").is_file()
