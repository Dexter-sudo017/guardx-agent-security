from __future__ import annotations

import json
import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.contracts import ContextualAuthorizationRequest, RuleMatch, RuleProvenance


PROJECT_ROOT = Path(__file__).resolve().parents[5]
RULES_PATH = PROJECT_ROOT / "configs" / "contextual_authorization_rules.json"


@lru_cache(maxsize=1)
def load_contextual_authorization_rules() -> dict[str, dict[str, Any]]:
    raw_bytes = RULES_PATH.read_bytes()
    raw = json.loads(raw_bytes.decode("utf-8"))
    if raw.get("schema_version") != "guardx-contextual-authorization-rules-v2":
        raise ValueError("unsupported contextual authorization rule schema")
    source_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    provenance = {
        "store_id": str(raw.get("store_id") or "guardx_contextual_rules"),
        "schema_version": str(raw["schema_version"]),
        "source_path": str(RULES_PATH),
        "source_sha256": source_sha256,
        "trust": "trusted_policy_store",
    }
    rules: dict[str, dict[str, Any]] = {}
    for item in raw.get("rules") or []:
        rule = dict(item)
        rule["provenance"] = provenance
        rule_id = str(rule["rule_id"])
        if rule_id in rules:
            raise ValueError(f"duplicate contextual authorization rule: {rule_id}")
        rules[rule_id] = rule
    return rules


def _matches(request: ContextualAuthorizationRequest, selectors: dict[str, Any]) -> bool:
    checks: list[bool] = []
    if selectors.get("sources"):
        checks.append(request.source in {str(item) for item in selectors["sources"]})
    if selectors.get("capabilities"):
        checks.append(request.requested_capability in {str(item) for item in selectors["capabilities"]})
    if selectors.get("data_classes"):
        checks.append(request.data_classification in {str(item) for item in selectors["data_classes"]})
    if selectors.get("sinks"):
        checks.append(request.sink in {str(item) for item in selectors["sinks"]})
    if selectors.get("destinations"):
        checks.append(str(request.destination or "") in {str(item) for item in selectors["destinations"]})
    if selectors.get("approval_required") is True:
        checks.append(bool(request.approval_required))
    # A rule selector is a conjunction across selector dimensions. Values within
    # one dimension are alternatives (for example, any listed source may match).
    return bool(checks) and all(checks)


def retrieve_contextual_authorization_rules(request: ContextualAuthorizationRequest) -> list[dict[str, Any]]:
    rules = load_contextual_authorization_rules()
    selected = [rule for rule in rules.values() if _matches(request, dict(rule.get("selectors") or {}))]
    selected.sort(key=lambda item: str(item["rule_id"]))
    return selected


def retrieve_rule_matches(request: ContextualAuthorizationRequest) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for rule in retrieve_contextual_authorization_rules(request):
        selectors = dict(rule.get("selectors") or {})
        matched_selectors: dict[str, Any] = {}
        for key, value in selectors.items():
            if key == "sources" and request.source in value:
                matched_selectors[key] = request.source
            elif key == "capabilities" and request.requested_capability in value:
                matched_selectors[key] = request.requested_capability
            elif key == "data_classes" and request.data_classification in value:
                matched_selectors[key] = request.data_classification
            elif key == "sinks" and request.sink in value:
                matched_selectors[key] = request.sink
            elif key == "destinations" and str(request.destination or "") in value:
                matched_selectors[key] = request.destination
            elif key == "approval_required" and value is True and request.approval_required:
                matched_selectors[key] = True
        matches.append(
            RuleMatch(
                rule_id=str(rule["rule_id"]),
                family=str(rule.get("family") or "unknown"),
                effect=rule.get("effect"),
                matched_selectors=matched_selectors,
                provenance=RuleProvenance.model_validate(rule["provenance"]),
            )
        )
    return matches
