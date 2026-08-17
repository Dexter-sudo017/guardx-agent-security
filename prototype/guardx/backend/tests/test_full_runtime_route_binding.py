from __future__ import annotations

import ast
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from app.approval import ApprovalStore
from app.authorization_runtime import AuthorizationRuntime
from app.capabilities import CapabilityGrant, CapabilityStore
from app.executor_secure.permit import PermitAuthority
from app.executor_secure.registry import SecureRunnerRegistry
from app.executor_secure.runtime import SecureExecutor
from app.executor_secure.sandbox import SandboxRun
from app.main import create_app
from app.services.integrated_runtime import IntegratedRuntimeService


APPROVAL_SECRET = b"route-test-approval-secret-32-bytes-minimum"
BACKEND_ROOT = Path(__file__).resolve().parents[1]


def _service(tmp_path: Path) -> tuple[IntegratedRuntimeService, SandboxRun]:
    sandbox = SandboxRun.create(tmp_path / "runs")
    authority = PermitAuthority(b"route-test-permit-secret-material")
    registry = SecureRunnerRegistry(sandbox, authority)
    capability_store = CapabilityStore(
        [
            CapabilityGrant(
                grant_id="route-file-write",
                subject_id="route-user",
                capability="file_write",
                issuer="route_test_trusted_store",
                issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
        ],
        store_id="route_test_store",
    )
    runtime = AuthorizationRuntime(
        registry,
        SecureExecutor(authority),
        ApprovalStore(tmp_path / "approvals.json", APPROVAL_SECRET),
        capability_store=capability_store,
    )
    return IntegratedRuntimeService(runtime), sandbox


def _payload(execution_id: str) -> dict:
    return {
        "execution_id": execution_id,
        "session_id": "route-session",
        "step_id": "write-step",
        "plan": {
            "plan_id": "route-plan",
            "planner_id": "trusted-test-planner",
            "steps": [
                {
                    "step_id": "write-step",
                    "capability": "file_write",
                    "input_ref": "route-input",
                    "constraints": {"tool": "workspace.file"},
                    "trust_boundary": {
                        "source": "user",
                        "trust_level": "trusted",
                        "executable": True,
                        "can_instruct_model": True,
                    },
                }
            ],
        },
        "authorization_context": {
            "context_id": "route-context",
            "principal_id": "route-user",
            "user_goal": "write the route result",
            "source": "authenticated_user",
            "source_trust": "trusted",
            "requested_capability": "file_write",
            "proposed_action": {"tool": "workspace.file"},
        },
        "args": {"operation": "write", "path": "route-result.txt", "content": "ok"},
    }


def test_route_executes_only_through_planner_authorization_binding(tmp_path: Path) -> None:
    service, sandbox = _service(tmp_path)
    app = create_app()
    app.state.integrated_runtime_service = service
    client = TestClient(app)
    response = client.post("/v1/runtime/actions/execute", json=_payload(sandbox.execution_id))
    assert response.status_code == 200
    assert response.json()["runner_invoked"] is True
    assert (sandbox.workspace / "route-result.txt").read_text(encoding="utf-8") == "ok"


def test_planner_capability_mismatch_is_rejected_before_executor(tmp_path: Path) -> None:
    service, sandbox = _service(tmp_path)
    app = create_app()
    app.state.integrated_runtime_service = service
    payload = _payload(sandbox.execution_id)
    payload["plan"]["steps"][0]["capability"] = "file_delete"
    response = TestClient(app).post("/v1/runtime/actions/execute", json=payload)
    assert response.status_code == 403
    assert not (sandbox.workspace / "route-result.txt").exists()


def test_unprovisioned_and_direct_executor_routes_are_unavailable(tmp_path: Path) -> None:
    app = create_app()
    client = TestClient(app)
    assert client.post("/v1/runtime/actions/execute", json=_payload("missing")).status_code == 503
    assert client.post("/v1/executor/execute", json={}).status_code == 404
    valid_contract_shape = {
        "session_id": "unconfigured",
        "authorization_decision": {"decision": "ALLOW"},
        "capability": "file_write",
        "tool": "workspace.file",
        "target": "workspace/result.txt",
        "arguments": {"operation": "write", "path": "result.txt", "content": "blocked"},
        "action_origin": {"authority": "policy_engine", "principal_id": "spoof", "trusted": True},
    }
    assert client.post("/v1/executor/executions", json=valid_contract_shape).status_code == 503


def test_secure_executor_invocations_are_statically_confined_to_authorization_runtime() -> None:
    callers: list[str] = []
    for path in (BACKEND_ROOT / "app").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr == "execute" and isinstance(node.func.value, ast.Attribute) and node.func.value.attr in {"executor", "_executor"}:
                callers.append(path.relative_to(BACKEND_ROOT).as_posix())
    assert callers == ["app/integration/executor_service.py", "app/integration/executor_service.py"]
