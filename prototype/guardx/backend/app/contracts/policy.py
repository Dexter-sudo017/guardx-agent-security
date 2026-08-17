from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.compat.authorization_vocabulary import r4a_to_canonical


PolicyRoute = Literal["allow", "review", "block"]
EnforcementAction = Literal["allow", "rewrite", "redact", "require_confirm", "terminate"]
AuditLevel = Literal["none", "summary", "full"]
AuthorizationDecision = Literal[
    "ALLOW",
    "ALLOW_WITH_CONSTRAINTS",
    "QUARANTINE_AND_CONTINUE",
    "REQUIRE_APPROVAL",
    "DENY_ACTION",
    "TERMINATE",
]
PolicyMode = Literal["legacy", "contextual_v2"]


class PolicyDecision(BaseModel):
    route: PolicyRoute
    action: EnforcementAction
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)
    required_guards: list[str] = Field(default_factory=list)
    audit_level: AuditLevel = "summary"


class SourceProvenance(BaseModel):
    """Origin metadata. It describes evidence and never grants authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str
    source_type: str
    trust: Literal["trusted", "bounded", "untrusted"]
    producer: str = "unknown"
    content_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuleProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    store_id: str
    schema_version: str
    source_path: str
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trust: Literal["trusted_policy_store"] = "trusted_policy_store"


class RuleMatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    family: str
    effect: AuthorizationDecision | None = None
    matched_selectors: dict[str, Any] = Field(default_factory=dict)
    provenance: RuleProvenance


class AuthorizationContext(BaseModel):
    """Complete input to authorization; authority is verified outside the model."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "guardx-authorization-context-v2"
    context_id: str = "unspecified"
    principal_id: str = "authenticated_user"
    user_goal: str
    source: str
    source_trust: Literal["trusted", "bounded", "untrusted"]
    provenance: SourceProvenance | None = None
    observation: str = ""
    proposed_action: dict[str, Any] = Field(default_factory=dict)
    requested_capability: str
    # Compatibility/audit snapshot only. Policy v2 never authorizes from this
    # field; grants must resolve through CapabilityStore.
    granted_capabilities: list[str] = Field(default_factory=list)
    data_classification: Literal["public", "internal", "private", "secret"] = "public"
    session_context: str = ""
    destination: str | None = None
    sink: Literal["local", "external", "unauthorized"] = "local"
    task_alignment: bool | None = None
    action_alignment: bool | None = None
    approval_required: bool = False
    action_origin: Literal["user_goal", "observation", "runtime_planned"] = "runtime_planned"
    task_lifecycle: Literal["active", "terminal"] = "active"
    approval_state: Literal["not_required", "pending", "approved", "denied", "unknown"] = "unknown"
    legacy_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


# Old name remains import-compatible while callers migrate to the v2 name.
ContextualAuthorizationRequest = AuthorizationContext


class AuthorizationFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "guardx-authorization-finding-v2"
    provider_id: str = "contextual_authorization_provider"
    source_authority: Literal["authorized_instruction", "observation_only", "trusted_policy", "unknown"] | str
    task_alignment: bool
    action_alignment: bool
    requested_capability: str
    capability_granted: bool
    data_flow: str
    matched_rules: list[str] = Field(default_factory=list)
    rule_matches: list[RuleMatch] = Field(default_factory=list)
    decision: AuthorizationDecision
    preserve_observation: bool = True
    continue_original_task: bool = True
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    uncertainty_reasons: list[str] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)
    model_version: str = "deterministic_policy_v2"
    evidence: dict[str, Any] = Field(default_factory=dict)

    @field_validator("decision", mode="before")
    @classmethod
    def normalize_legacy_decision(cls, value: Any) -> Any:
        if isinstance(value, str):
            return r4a_to_canonical(value)
        return value


class PolicyV2Result(BaseModel):
    schema_version: str = "guardx-policy-v2-result-v2"
    mode: PolicyMode = "contextual_v2"
    finding: AuthorizationFinding
    policy_decision: PolicyDecision
    enforcement: AuthorizationDecision
    legacy_policy_unchanged: bool = True
    review_required: bool = False
    continuation: dict[str, Any] = Field(default_factory=dict)
