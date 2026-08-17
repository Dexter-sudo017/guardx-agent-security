from typing import Any


def decision_record(row: dict[str, Any]) -> dict[str, Any]:
    record = row.get("decision_record")
    return record if isinstance(record, dict) else {}


def experiment_metadata(record: dict[str, Any]) -> dict[str, Any]:
    envelope = record.get("envelope") if isinstance(record.get("envelope"), dict) else {}
    metadata = envelope.get("metadata") if isinstance(envelope.get("metadata"), dict) else {}
    experiment = envelope.get("experiment") if isinstance(envelope.get("experiment"), dict) else {}
    return {**metadata, **experiment}


def decision_policy_profile(record: dict[str, Any]) -> str:
    decision = record.get("policy_decision") if isinstance(record.get("policy_decision"), dict) else {}
    constraints = decision.get("constraints") if isinstance(decision.get("constraints"), dict) else {}
    experiment = experiment_metadata(record)
    return str(constraints.get("policy_profile") or experiment.get("policy_profile") or "unknown")
