from __future__ import annotations

from typing import Any

from app.models import AnalysisResult


GUARDED_SURFACES = {"agent", "tool_observation", "plugin", "rag"}

BENIGN_BOUNDARY_MARKERS = (
    "approved_governance_lookup",
    "allow_with_citation",
    "public_governance_document",
    "governance document",
    "approved governance",
    "citation boundary",
    "trusted_network",
    "allowlisted governance",
    "read_only_workspace_file",
    "read_only_database_audit",
    "read_only_database_capability",
    "benign_plugin_manifest_audit",
    "approved_plugin_manifest",
    "approved_plugin_manifest_review",
    "trusted_plugin_update",
    "source_uri_present",
    "provenance_hash_present",
    "rollback_supported",
    "disabled network export",
    "no network export",
    "quoted attack analysis",
    "evidence only",
)


def _available_tools_text(case: dict[str, Any]) -> str:
    return " ".join(str(item).lower() for item in case.get("available_tools") or [])


def _combined_text(case: dict[str, Any], text: str) -> str:
    boundary = str(case.get("trust_boundary") or "").lower()
    tools = _available_tools_text(case)
    return " ".join([text.lower(), boundary, tools])


def analyze_case_metadata_signal(case: dict[str, Any], text: str) -> AnalysisResult:
    """Detect cross-layer side-effect risks from case metadata and tool affordances.

    This guard intentionally looks beyond raw text. It considers the surface,
    trust boundary, available tools, and side-effect hints so that RAG/tool/agent
    cases are not judged as ordinary chat messages.
    """

    surface = str(case.get("surface") or "").lower()
    if surface not in GUARDED_SURFACES:
        return AnalysisResult(risk_score=0.0, labels=[], evidence=[], metadata={"enabled": False, "reason": "surface_not_guarded"})

    combined = _combined_text(case, text)
    benign_boundary = any(marker in combined for marker in BENIGN_BOUNDARY_MARKERS)
    labels: list[str] = []

    if not benign_boundary and any(marker in combined for marker in ("code_execution_capability", "shell_exec", "code execution")):
        if any(marker in combined for marker in ("credential", "environment inspection", "runtime secrets", "secret", "sensitive environment")):
            labels.append("metadata_code_execution_secret_probe")

    if not benign_boundary and any(marker in combined for marker in ("network_capability", "http_get", "network export")):
        if any(marker in combined for marker in ("export", "exfiltration", "private workspace", "unapproved network")):
            labels.append("metadata_network_exfiltration_probe")

    if not benign_boundary and any(marker in combined for marker in ("database_capability", "db_query", "database")):
        if any(marker in combined for marker in ("destructive", "mutation", "modify", "delete")):
            labels.append("metadata_database_mutation_probe")

    if surface == "plugin" and any(marker in combined for marker in ("no constraint", "lacks rollback", "unknown", "broad read/network", "broad read")):
        labels.append("metadata_plugin_provenance_gap")

    labels = sorted(set(labels))
    if not labels:
        return AnalysisResult(
            risk_score=0.0,
            labels=[],
            evidence=["side_effect_metadata_guard=no_signal"],
            metadata={"enabled": True, "benign_boundary": benign_boundary},
        )

    return AnalysisResult(
        risk_score=min(1.0, 0.42 + 0.18 * (len(labels) - 1)),
        labels=labels,
        evidence=[f"side_effect_metadata_guard={label}" for label in labels],
        metadata={"enabled": True, "benign_boundary": benign_boundary, "surface": surface},
    )
