from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[5]
DEFAULT_DECODER_ROOT = PROJECT_ROOT.parent / "srtp" / "eaas-privacy-master" / "evaluation" / "decoder_probe"
SCHEMA_VERSION = "guardx-decoder-probe-summary-v1"


def latest_decoder_result(root: Path = DEFAULT_DECODER_ROOT) -> Path | None:
    if not root.exists():
        return None
    candidates = [path for path in root.glob("*/results.json") if path.is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda item: item.stat().st_mtime)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _contains_raw_text(data: dict[str, Any]) -> bool:
    rows = data.get("rows") if isinstance(data.get("rows"), dict) else {}
    for values in rows.values():
        if not isinstance(values, list):
            continue
        for row in values:
            if isinstance(row, dict) and ("source_text" in row or "reconstruction" in row):
                return True
    return False


def build_decoder_probe_summary(*, source: Path | None = None, run_id: str = "local-decoder-probe-import") -> dict[str, Any]:
    result_path = source or latest_decoder_result()
    if result_path is None:
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "available": False,
            "ready": False,
            "missing_reason": "decoder_probe_results_not_found",
            "expected_root": str(DEFAULT_DECODER_ROOT),
        }
    data = _load_json(result_path)
    metrics = data.get("reconstruction_metrics") if isinstance(data.get("reconstruction_metrics"), list) else []
    findings = data.get("findings") if isinstance(data.get("findings"), list) else []
    max_risk = max([float(item.get("risk_score") or 0.0) for item in findings] or [0.0])
    max_token_f1 = max([float(item.get("token_f1") or 0.0) for item in metrics] or [0.0])
    contains_raw_text = _contains_raw_text(data)
    eval_only = data.get("eval_only") is True
    production_routing = data.get("production_routing") is True
    blocking_reasons = []
    if not metrics or not findings:
        blocking_reasons.append("missing_metrics_or_findings")
    if not eval_only:
        blocking_reasons.append("not_eval_only")
    if production_routing:
        blocking_reasons.append("production_routing_enabled")
    if contains_raw_text:
        blocking_reasons.append("raw_text_or_reconstruction_present")
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "available": True,
        "ready": not blocking_reasons,
        "blocking_reasons": blocking_reasons,
        "source_path": str(result_path),
        "source_schema_version": data.get("schema_version"),
        "source_run_id": data.get("run_id"),
        "provider_id": data.get("provider_id"),
        "eval_only": eval_only,
        "production_routing": production_routing,
        "glue_task": data.get("glue_task"),
        "model_name": data.get("model_name"),
        "train_size": data.get("train_size"),
        "eval_size": data.get("eval_size"),
        "variants": data.get("variants") or [],
        "attacks": data.get("attacks") or [],
        "max_risk_score": round(max_risk, 6),
        "max_token_f1": round(max_token_f1, 6),
        "contains_raw_text": contains_raw_text,
        "raw_text_policy": "omit_source_and_reconstruction_by_default",
        "risk_findings": findings,
        "reconstruction_metrics": metrics,
    }
