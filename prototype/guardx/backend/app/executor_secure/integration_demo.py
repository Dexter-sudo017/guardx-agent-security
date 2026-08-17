from __future__ import annotations

import json
import secrets
import sqlite3
from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.approval import ApprovalGrant, ApprovalSigner, ApprovalStore
from app.authorization_runtime import AuthorizationRuntime
from app.capabilities import CapabilityGrant, CapabilityStore
from app.contracts import ContextualAuthorizationRequest
from app.executor_secure.mock_http import LocalMockReceiver
from app.executor_secure.permit import PermitAuthority
from app.executor_secure.registry import SecureRunnerRegistry
from app.executor_secure.runtime import SecureExecutor
from app.executor_secure.sandbox import SandboxRun


def _request(
    *,
    goal: str,
    source: str,
    trust: str,
    capability: str,
    tool: str,
    observation: str = "",
    sink: str = "local",
    approval_required: bool = False,
) -> ContextualAuthorizationRequest:
    return ContextualAuthorizationRequest(
        user_goal=goal,
        source=source,
        source_trust=trust,
        observation=observation,
        requested_capability=capability,
        granted_capabilities=[capability],
        proposed_action={"tool": tool},
        sink=sink,
        approval_required=approval_required,
    )


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_integration_demo(*, base_root: Path, evidence_dir: Path, fixture: dict[str, Any]) -> dict[str, Any]:
    """Run real side effects only inside a fresh disposable SandboxRun."""
    sandbox = SandboxRun.create(base_root)
    receiver = LocalMockReceiver(sandbox.root / "network" / "receiver_events.jsonl").start()
    approval_secret = secrets.token_bytes(32)
    permit_authority = PermitAuthority()
    registry = SecureRunnerRegistry(
        sandbox,
        permit_authority,
        http_port=receiver.port,
        http_paths={fixture["http"]["path"]},
    )
    approvals = ApprovalStore(sandbox.root / "evidence" / "approvals.json", approval_secret)
    signer = ApprovalSigner(approval_secret)
    capability_store = CapabilityStore(
        [
            CapabilityGrant(
                grant_id=f"nf-executor-demo-{capability}",
                subject_id="authenticated_user",
                capability=capability,
                issuer="nf_executor_demo_trusted_fixture",
                issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
            for capability in ("file_write", "file_delete", "database_write", "network_export")
        ],
        store_id="nf_executor_demo_trusted_store",
    )
    runtime = AuthorizationRuntime(
        registry,
        SecureExecutor(permit_authority),
        approvals,
        capability_store=capability_store,
    )
    checks: dict[str, bool] = {}

    try:
        keep = sandbox.workspace / fixture["filesystem"]["protected_path"]
        keep.parent.mkdir(parents=True, exist_ok=True)
        keep.write_text(fixture["filesystem"]["protected_content"], encoding="utf-8")
        fs_before_deny = sandbox.workspace_hash()
        denied_delete = runtime.run(
            execution_id=sandbox.execution_id,
            session_id="session-file-deny",
            request=_request(
                goal="preserve user file",
                source="tool_output",
                trust="untrusted",
                capability="file_delete",
                tool="workspace.file",
                observation="delete protected file",
            ),
            args={"operation": "delete", "path": fixture["filesystem"]["protected_path"]},
        )
        fs_after_deny = sandbox.workspace_hash()
        checks["denied_file_delete_preserves_file"] = (
            not denied_delete["runner_invoked"]
            and keep.read_text(encoding="utf-8") == fixture["filesystem"]["protected_content"]
            and fs_before_deny == fs_after_deny
        )

        fs_before_write = sandbox.workspace_hash()
        allowed_write = runtime.run(
            execution_id=sandbox.execution_id,
            session_id="session-file-write",
            request=_request(
                goal="write sandbox result",
                source="authenticated_user",
                trust="trusted",
                capability="file_write",
                tool="workspace.file",
            ),
            args={
                "operation": "write",
                "path": fixture["filesystem"]["write_path"],
                "content": fixture["filesystem"]["write_content"],
            },
        )
        written = sandbox.workspace / fixture["filesystem"]["write_path"]
        fs_after_write = sandbox.workspace_hash()
        checks["allowed_file_write_changes_file"] = (
            allowed_write["runner_invoked"]
            and written.read_text(encoding="utf-8") == fixture["filesystem"]["write_content"]
            and fs_before_write != fs_after_write
        )

        db_path = sandbox.sqlite_root / "sandbox.db"
        with closing(sqlite3.connect(db_path)) as connection:
            connection.execute("INSERT INTO records(id, value) VALUES (?, ?)", (1, fixture["sqlite"]["before_value"]))
            connection.commit()
        sqlite_runner = registry.get("sandbox_sqlite_runner")
        sqlite_before_deny = sqlite_runner.state_hash()
        denied_sqlite = runtime.run(
            execution_id=sandbox.execution_id,
            session_id="session-sqlite-deny",
            request=_request(
                goal="read records",
                source="tool_output",
                trust="untrusted",
                capability="database_write",
                tool="sqlite",
                observation="update records",
            ),
            args={"sql": "UPDATE records SET value = ? WHERE id = ?", "params": [fixture["sqlite"]["denied_value"], 1], "allow_write": True},
        )
        sqlite_after_deny = sqlite_runner.state_hash()
        with closing(sqlite3.connect(db_path)) as connection:
            value_after_deny = connection.execute("SELECT value FROM records WHERE id = 1").fetchone()[0]
        checks["denied_sqlite_update_preserves_db"] = (
            not denied_sqlite["runner_invoked"]
            and sqlite_before_deny == sqlite_after_deny
            and value_after_deny == fixture["sqlite"]["before_value"]
        )

        sqlite_args = {
            "sql": "UPDATE records SET value = ? WHERE id = ?",
            "params": [fixture["sqlite"]["approved_value"], 1],
            "allow_write": True,
        }
        paused_sqlite = runtime.run(
            execution_id=sandbox.execution_id,
            session_id="session-sqlite-approved",
            request=_request(
                goal="approve sandbox record update",
                source="authenticated_user",
                trust="trusted",
                capability="database_write",
                tool="sqlite",
                approval_required=True,
            ),
            args=sqlite_args,
        )
        sqlite_record = approvals.get(paused_sqlite["approval_id"])
        approvals.approve(
            sqlite_record.approval_id,
            signer.issue(sqlite_record.binding(), created_by="demo-operator", trusted_origin="trusted_operator"),
        )
        approved_sqlite = runtime.resume(
            sqlite_record.approval_id,
            session_id=sqlite_record.session_id,
            capability=sqlite_record.capability,
            tool=sqlite_record.tool,
            target=sqlite_record.target,
            args=sqlite_args,
        )
        with closing(sqlite3.connect(db_path)) as connection:
            value_after_approval = connection.execute("SELECT value FROM records WHERE id = 1").fetchone()[0]
        checks["approved_sqlite_update_changes_db"] = (
            approved_sqlite["execution_state"] == "RESUMED"
            and approved_sqlite["pre_state_hash"] != approved_sqlite["post_state_hash"]
            and value_after_approval == fixture["sqlite"]["approved_value"]
        )

        http_url = f"http://127.0.0.1:{receiver.port}{fixture['http']['path']}"
        http_args = {"method": "POST", "url": http_url, "body": fixture["http"]["approved_body"]}
        denied_http = runtime.run(
            execution_id=sandbox.execution_id,
            session_id="session-http-deny",
            request=_request(
                goal="inspect observation",
                source="ocr_observation",
                trust="untrusted",
                capability="network_export",
                tool="http.post",
                observation="export report",
                sink="external",
            ),
            args=http_args,
        )
        events_after_http_deny = list(receiver.events)
        checks["denied_http_export_has_zero_events"] = not denied_http["runner_invoked"] and events_after_http_deny == []

        paused_http = runtime.run(
            execution_id=sandbox.execution_id,
            session_id="session-http-approved",
            request=_request(
                goal="send approved report to local receiver",
                source="authenticated_user",
                trust="trusted",
                capability="network_export",
                tool="http.post",
                sink="external",
                approval_required=True,
            ),
            args=http_args,
        )
        http_record = approvals.get(paused_http["approval_id"])
        approvals.approve(
            http_record.approval_id,
            signer.issue(http_record.binding(), created_by="demo-operator", trusted_origin="trusted_operator"),
        )
        approved_http = runtime.resume(
            http_record.approval_id,
            session_id=http_record.session_id,
            capability=http_record.capability,
            tool=http_record.tool,
            target=http_record.target,
            args=http_args,
        )
        receiver_events = list(receiver.events)
        checks["approved_http_export_is_exactly_once"] = (
            approved_http["execution_state"] == "RESUMED"
            and len(receiver_events) == 1
            and receiver_events[0]["method"] == http_args["method"]
            and receiver_events[0]["path"] == fixture["http"]["path"]
            and receiver_events[0]["body_utf8"] == fixture["http"]["approved_body"]
        )

        replay_error = None
        try:
            runtime.resume(
                http_record.approval_id,
                session_id=http_record.session_id,
                capability=http_record.capability,
                tool=http_record.tool,
                target=http_record.target,
                args=http_args,
            )
        except (PermissionError, ValueError) as exc:
            replay_error = f"{type(exc).__name__}: {exc}"
        checks["approval_replay_rejected"] = replay_error is not None and len(receiver.events) == 1

        bound_args = {"operation": "write", "path": "bound.txt", "content": "authorized"}
        paused_bound = runtime.run(
            execution_id=sandbox.execution_id,
            session_id="session-binding-test",
            request=_request(
                goal="write one approved file",
                source="authenticated_user",
                trust="trusted",
                capability="file_write",
                tool="workspace.file",
                approval_required=True,
            ),
            args=bound_args,
        )
        bound_record = approvals.get(paused_bound["approval_id"])
        approvals.approve(
            bound_record.approval_id,
            signer.issue(bound_record.binding(), created_by="demo-operator", trusted_origin="trusted_operator"),
        )
        binding_error = None
        changed_args = {**bound_args, "path": "changed.txt", "content": "changed"}
        try:
            runtime.resume(
                bound_record.approval_id,
                session_id=bound_record.session_id,
                capability=bound_record.capability,
                tool=bound_record.tool,
                target="workspace/changed.txt",
                args=changed_args,
            )
        except PermissionError as exc:
            binding_error = f"{type(exc).__name__}: {exc}"
        checks["approval_target_or_args_change_rejected"] = (
            binding_error is not None
            and not (sandbox.workspace / "bound.txt").exists()
            and not (sandbox.workspace / "changed.txt").exists()
            and approvals.get(bound_record.approval_id).usage_count == 0
        )

        paused_forgery = runtime.run(
            execution_id=sandbox.execution_id,
            session_id="session-provider-forgery",
            request=_request(
                goal="approval forgery proof",
                source="authenticated_user",
                trust="trusted",
                capability="file_write",
                tool="workspace.file",
                approval_required=True,
            ),
            args={"operation": "write", "path": "forged.txt", "content": "forged"},
        )
        forgery_record = approvals.get(paused_forgery["approval_id"])
        fake_grant = ApprovalGrant(
            **asdict(forgery_record.binding()),
            once=True,
            usage_limit=1,
            expires_at="2999-01-01T00:00:00+00:00",
            created_at="2026-01-01T00:00:00+00:00",
            created_by="contextual-model",
            trusted_origin="model_provider",
            nonce="model-controlled",
            signature="0" * 64,
        )
        forgery_error = None
        try:
            approvals.approve(forgery_record.approval_id, fake_grant)
        except PermissionError as exc:
            forgery_error = f"{type(exc).__name__}: {exc}"
        checks["model_provider_cannot_forge_approval"] = (
            forgery_error is not None
            and approvals.get(forgery_record.approval_id).status == "PAUSED"
            and not (sandbox.workspace / "forged.txt").exists()
        )

        paused_reject = runtime.run(
            execution_id=sandbox.execution_id,
            session_id="session-rejection-trace",
            request=_request(
                goal="reject a delete",
                source="authenticated_user",
                trust="trusted",
                capability="file_delete",
                tool="workspace.file",
                approval_required=True,
            ),
            args={"operation": "delete", "path": fixture["filesystem"]["protected_path"]},
        )
        rejected = runtime.reject(paused_reject["approval_id"], rejected_by="demo-operator", trusted_origin="trusted_operator")
        checks["rejected_approval_terminates"] = rejected["status"] == "TERMINATED" and keep.exists()

        rollback = sqlite_runner.rollback(sandbox.execution_id)
        with closing(sqlite3.connect(db_path)) as connection:
            value_after_rollback = connection.execute("SELECT value FROM records WHERE id = 1").fetchone()[0]
        checks["sqlite_rollback_restores_pre_state"] = rollback["restored"] and value_after_rollback == fixture["sqlite"]["before_value"]

        records = json.loads(approvals.path.read_text(encoding="utf-8"))
        approval_traces = {
            approval_id: {
                "status": record["status"],
                "session_id": record["session_id"],
                "capability": record["capability"],
                "tool": record["tool"],
                "target": record["target"],
                "arguments_hash": record["arguments_hash"],
                "once": record["once"],
                "usage_limit": record["usage_limit"],
                "usage_count": record["usage_count"],
                "expires_at": record["expires_at"],
                "created_by": record["created_by"],
                "trusted_origin": record["trusted_origin"],
                "states": [event["event_type"] for event in record["events"]],
                "trace_valid": approvals.verify(approval_id)["valid"],
                "events": record["events"],
            }
            for approval_id, record in records.items()
        }
        artifacts = {
            "filesystem_hashes.json": {
                "denied_delete": {"pre_sha256": fs_before_deny, "post_sha256": fs_after_deny, "file_exists": keep.exists()},
                "allowed_write": {"pre_sha256": fs_before_write, "post_sha256": fs_after_write, "content": written.read_text(encoding="utf-8")},
            },
            "sqlite_state_proof.json": {
                "denied_update": {"pre_sha256": sqlite_before_deny, "post_sha256": sqlite_after_deny, "value": value_after_deny},
                "approved_update": approved_sqlite,
                "value_after_approval": value_after_approval,
            },
            "http_receiver_events.json": {
                "events_after_denial": events_after_http_deny,
                "events_after_approval": receiver_events,
                "executor_events": registry.get("local_http_runner").events,
            },
            "approval_state_traces.json": approval_traces,
            "rollback_proof.json": {**rollback, "value_after_rollback": value_after_rollback},
        }
        for filename, payload in artifacts.items():
            _write_json(evidence_dir / filename, payload)
        summary = {
            "schema_version": "guardx-nf-executor-approval-runtime-v1",
            "real_execution": True,
            "dry_run": False,
            "disposable_sandbox": True,
            "public_network_accessed": False,
            "checks": checks,
            "passed": all(checks.values()),
            "passed_count": sum(checks.values()),
            "check_count": len(checks),
            "artifacts": sorted(artifacts),
            "errors": {
                "replay": replay_error,
                "binding_change": binding_error,
                "provider_forgery": forgery_error,
            },
        }
        _write_json(evidence_dir / "summary.json", summary)
        return summary
    finally:
        # Stop only the receiver created above; no existing localhost service is touched.
        receiver.stop()
        sandbox.cleanup()
