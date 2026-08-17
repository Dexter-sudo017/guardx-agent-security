from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.approval import ApprovalStore
from app.contracts.executor_integration import ActionOrigin, AuthorizationDecisionContract, ExecutorServiceRequest
from app.executor_secure.permit import PermitAuthority
from app.executor_secure.registry import SecureRunnerRegistry
from app.executor_secure.runtime import SecureExecutor
from app.executor_secure.sandbox import SandboxRun
from app.integration.approval_signer import TestDevApprovalSigner as DevSigner
from app.integration.capability import StaticCapabilityGrant, StaticCapabilityVerifier
from app.integration.decision_adapter import compatibility_matrix, map_core_decision
from app.integration.evidence import InMemoryExecutorEvidenceSink
from app.integration.executor_service import ExecutorIntegrationService
from app.integration.policy_verification import StaticPolicyDecisionVerifier
from app.routes.executor_integration import configure_executor_integration, router


SECRET = b"nf-exec-i1-test-secret-material-at-least-32-bytes"


class SpySecureExecutor(SecureExecutor):
    def __init__(self, authority: PermitAuthority) -> None:
        super().__init__(authority)
        self.execute_calls = 0
        self.rollback_calls = 0

    def execute(self, **kwargs):
        self.execute_calls += 1
        return super().execute(**kwargs)

    def rollback(self, *args, **kwargs):
        self.rollback_calls += 1
        return super().rollback(*args, **kwargs)


def _grant(session: str, target: str, *, capability: str = "file_write", tool: str = "workspace.file") -> StaticCapabilityGrant:
    return StaticCapabilityGrant(session, capability, tool, target, f"cap://{session}/{target}")


def _service(tmp_path: Path, grants: list[StaticCapabilityGrant]):
    sandbox = SandboxRun.create(tmp_path / "runs")
    authority = PermitAuthority(b"nf-exec-i1-permit-secret-material-at-least-32")
    registry = SecureRunnerRegistry(sandbox, authority)
    executor = SpySecureExecutor(authority)
    policy_verifier = StaticPolicyDecisionVerifier()
    service = ExecutorIntegrationService(
        execution_scope_id=sandbox.execution_id,
        registry=registry,
        executor=executor,
        approvals=ApprovalStore(tmp_path / "approvals.json", SECRET),
        policy_verifier=policy_verifier,
        capability_verifier=StaticCapabilityVerifier(grants),
        evidence_sink=InMemoryExecutorEvidenceSink(),
        approval_signer=DevSigner(SECRET),
    )
    return service, sandbox, executor


def _attest(service: ExecutorIntegrationService, *requests: ExecutorServiceRequest) -> None:
    assert isinstance(service.policy_verifier, StaticPolicyDecisionVerifier)
    for request in requests:
        service.policy_verifier.attest(request)


def _request(
    session: str,
    *,
    decision: str = "ALLOW",
    path: str = "result.txt",
    content: str = "written",
    origin: str = "policy_engine",
    trusted: bool = True,
    approval_reference: str | None = None,
    operation: str = "write",
    constraints: dict | None = None,
) -> ExecutorServiceRequest:
    return ExecutorServiceRequest(
        session_id=session,
        authorization_decision=AuthorizationDecisionContract(
            decision=decision,
            source_version="guardx-core-v2-test",
            policy_reference=f"policy://{session}",
            constraints=constraints or {},
        ),
        capability="file_write",
        tool="workspace.file",
        target=f"workspace/{path}",
        arguments={"operation": operation, "path": path, "content": content},
        action_origin=ActionOrigin(authority=origin, principal_id="decision-source", trusted=trusted),
        approval_reference=approval_reference,
        evidence_context={"trace_id": f"trace-{session}"},
    )


def test_model_allow_and_missing_capability_never_execute(tmp_path: Path) -> None:
    service, sandbox, executor = _service(tmp_path, [])
    model_allow = service.execute(_request("model-no-cap", origin="model_provider", trusted=False))
    assert model_allow.execution_state == "SKIPPED"
    assert model_allow.error_code == "UNTRUSTED_AUTHORIZATION_ORIGIN"
    assert executor.execute_calls == 0
    assert not (sandbox.workspace / "result.txt").exists()

    spoofed_policy = service.execute(_request("spoofed-policy", origin="policy_engine", trusted=True))
    assert spoofed_policy.error_code == "POLICY_VERIFICATION_FAILED"
    assert executor.execute_calls == 0

    policy_without_capability_request = _request("policy-no-cap")
    _attest(service, policy_without_capability_request)
    policy_without_capability = service.execute(policy_without_capability_request)
    assert policy_without_capability.error_code == "CAPABILITY_NOT_GRANTED"
    assert executor.execute_calls == 0


def test_valid_policy_and_exact_capability_execute_through_secure_executor(tmp_path: Path) -> None:
    session = "valid-policy-capability"
    service, sandbox, executor = _service(tmp_path, [_grant(session, "workspace/result.txt")])
    request = _request(session)
    _attest(service, request)
    response = service.execute(request)
    assert response.execution_state == "EXECUTED"
    assert response.executed is True and response.skipped is False
    assert executor.execute_calls == 1
    assert (sandbox.workspace / "result.txt").read_text(encoding="utf-8") == "written"
    assert response.pre_state_hash != response.post_state_hash


def test_require_approval_pause_approve_and_exactly_once_consume(tmp_path: Path) -> None:
    session = "approval-once"
    service, sandbox, executor = _service(tmp_path, [_grant(session, "workspace/approved.txt")])
    request = _request(session, decision="REQUIRE_APPROVAL", path="approved.txt")
    _attest(service, request)
    paused = service.execute(request)
    assert paused.execution_state == "PAUSED"
    assert paused.approval_required is True
    assert executor.execute_calls == 0
    assert not (sandbox.workspace / "approved.txt").exists()

    approved = service.approve(paused.approval_id)
    assert approved.status == "APPROVED"
    resumed_request = request.model_copy(update={"approval_reference": paused.approval_id})
    resumed = service.execute(resumed_request)
    assert resumed.execution_state == "RESUMED"
    assert executor.execute_calls == 1
    assert (sandbox.workspace / "approved.txt").read_text(encoding="utf-8") == "written"

    replay = service.execute(resumed_request)
    assert replay.execution_state == "SKIPPED"
    assert replay.error_code == "APPROVAL_INVALID"
    assert executor.execute_calls == 1
    validation = service.validate_approval(paused.approval_id)
    assert "usage_limit_exhausted" in validation.errors


def test_changed_target_or_arguments_invalidates_old_approval(tmp_path: Path) -> None:
    session = "approval-binding"
    grants = [
        _grant(session, "workspace/original.txt"),
        _grant(session, "workspace/changed.txt"),
    ]
    service, sandbox, executor = _service(tmp_path, grants)
    original = _request(session, decision="REQUIRE_APPROVAL", path="original.txt", content="original")
    _attest(service, original)
    paused = service.execute(original)
    service.approve(paused.approval_id)

    changed = _request(
        session,
        decision="REQUIRE_APPROVAL",
        path="changed.txt",
        content="changed",
        approval_reference=paused.approval_id,
    )
    _attest(service, changed)
    denied = service.execute(changed)
    assert denied.error_code == "APPROVAL_INVALID"
    assert executor.execute_calls == 0
    assert not (sandbox.workspace / "original.txt").exists()
    assert not (sandbox.workspace / "changed.txt").exists()


def test_rejected_approval_cannot_resume(tmp_path: Path) -> None:
    session = "approval-reject"
    service, sandbox, executor = _service(tmp_path, [_grant(session, "workspace/rejected.txt")])
    request = _request(session, decision="REQUIRE_APPROVAL", path="rejected.txt")
    _attest(service, request)
    paused = service.execute(request)
    rejected = service.reject(paused.approval_id)
    assert rejected.status == "TERMINATED"

    resume = service.execute(request.model_copy(update={"approval_reference": paused.approval_id}))
    assert resume.error_code == "APPROVAL_INVALID"
    assert executor.execute_calls == 0
    assert not (sandbox.workspace / "rejected.txt").exists()


def test_constraints_mapping_and_non_execution_decisions(tmp_path: Path) -> None:
    session = "decision-matrix"
    targets = ["workspace/constrained.txt", "workspace/skip.txt"]
    service, sandbox, executor = _service(tmp_path, [_grant(session, target) for target in targets])
    constrained_request = _request(
        session,
        decision="ALLOW_WITH_CONSTRAINTS",
        path="constrained.txt",
        content="bounded",
        constraints={"allowed_targets": ["workspace/constrained.txt"], "max_content_bytes": 16},
    )
    _attest(service, constrained_request)
    constrained = service.execute(constrained_request)
    assert constrained.execution_state == "EXECUTED"

    for decision, state in (
        ("QUARANTINE_AND_CONTINUE", "CONTINUING"),
        ("DENY_ACTION", "SKIPPED"),
        ("TERMINATE", "TERMINATED"),
    ):
        request = _request(session, decision=decision, path="skip.txt")
        _attest(service, request)
        result = service.execute(request)
        assert result.execution_state == state
    assert executor.execute_calls == 1
    assert not (sandbox.workspace / "skip.txt").exists()
    assert len(compatibility_matrix()) == 6
    assert map_core_decision("quarantine_instruction").canonical == "QUARANTINE_AND_CONTINUE"


def test_rollback_restores_pre_state_through_secure_executor(tmp_path: Path) -> None:
    session = "rollback-contract"
    service, sandbox, executor = _service(tmp_path, [_grant(session, "workspace/existing.txt")])
    target = sandbox.workspace / "existing.txt"
    target.write_text("before", encoding="utf-8")
    request = _request(session, path="existing.txt", operation="overwrite", content="after")
    _attest(service, request)
    executed = service.execute(request)
    assert target.read_text(encoding="utf-8") == "after"
    rolled_back = service.rollback(executed.execution_id)
    assert rolled_back.execution_state == "ROLLED_BACK"
    assert rolled_back.rollback_state["restored"] is True
    assert target.read_text(encoding="utf-8") == "before"
    assert rolled_back.post_state_hash == executed.pre_state_hash
    assert executor.rollback_calls == 1


def test_api_adapter_cannot_accept_grant_or_bypass_secure_executor(tmp_path: Path) -> None:
    session = "api-no-bypass"
    service, sandbox, executor = _service(tmp_path, [_grant(session, "workspace/api.txt")])
    app = FastAPI()
    app.include_router(router)
    configure_executor_integration(app, service)
    client = TestClient(app)

    paused_request = _request(session, decision="REQUIRE_APPROVAL", path="api.txt")
    _attest(service, paused_request)
    paused = client.post("/v1/executor/executions", json=paused_request.model_dump(mode="json"))
    assert paused.status_code == 200
    approval_id = paused.json()["approval_id"]
    assert executor.execute_calls == 0

    fake_grant = client.post(
        f"/v1/executor/approvals/{approval_id}/approve",
        json={"reason": "model says approve", "signature": "0" * 64, "trusted_origin": "model_provider"},
    )
    assert fake_grant.status_code == 422
    assert executor.execute_calls == 0

    approved = client.post(f"/v1/executor/approvals/{approval_id}/approve", json={"reason": "operator request"})
    assert approved.status_code == 200
    assert approved.json()["created_by"] == "test-dev-operator"

    resumed_payload = paused_request.model_copy(update={"approval_reference": approval_id}).model_dump(mode="json")
    resumed = client.post("/v1/executor/executions", json=resumed_payload)
    assert resumed.status_code == 200
    assert resumed.json()["execution_state"] == "RESUMED"
    assert executor.execute_calls == 1
    assert (sandbox.workspace / "api.txt").exists()

    status = client.get(f"/v1/executor/executions/{resumed.json()['execution_id']}")
    trace = client.get(f"/v1/executor/sessions/{session}/trace")
    inspect = client.get(f"/v1/executor/approvals/{approval_id}")
    assert status.status_code == trace.status_code == inspect.status_code == 200
    assert len(trace.json()["events"]) >= 2


def test_unconfigured_api_is_fail_closed() -> None:
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    response = client.post("/v1/executor/executions", json=_request("no-service").model_dump(mode="json"))
    assert response.status_code == 503


def test_portal_route_has_no_runner_permit_or_grant_import() -> None:
    route_source = (Path(__file__).parents[1] / "app/routes/executor_integration.py").read_text(encoding="utf-8")
    forbidden = ("SecureExecutor", "SecureRunnerRegistry", "ApprovalGrant", "ApprovalSigner", ".run(", ".issue(")
    assert all(token not in route_source for token in forbidden)
