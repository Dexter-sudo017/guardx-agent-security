from dataclasses import replace
from pathlib import Path
import time

import pytest

from app.approval import ApprovalGrant, ApprovalSigner, ApprovalStore


SECRET = b"approval-test-secret-material-32-bytes-minimum"


def _paused(store: ApprovalStore):
    return store.create(
        execution_id="gxexec-approval-test",
        session_id="session-1",
        request={"source": "authenticated_user"},
        runner_id="local_http_runner",
        capability="network_export",
        tool="http.post",
        target="http://127.0.0.1:8123/echo",
        args={"method": "POST", "url": "http://127.0.0.1:8123/echo", "body": "ok"},
    )


def test_full_approval_state_machine_and_one_shot_consumption(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "approvals.json", SECRET)
    signer = ApprovalSigner(SECRET)
    record = _paused(store)
    assert record.status == "PAUSED"
    assert [event["event_type"] for event in record.events] == ["RUNNING", "REQUIRE_APPROVAL", "PAUSED"]

    grant = signer.issue(record.binding(), created_by="operator-1", trusted_origin="trusted_operator")
    assert store.approve(record.approval_id, grant).status == "APPROVED"
    resumed = store.consume(
        record.approval_id,
        session_id=record.session_id,
        capability=record.capability,
        tool=record.tool,
        target=record.target,
        args=record.args,
    )
    assert resumed.status == "RESUMED"
    assert resumed.once is True
    assert resumed.usage_count == resumed.usage_limit == 1
    with pytest.raises(PermissionError, match="usage limit exhausted"):
        store.consume(
            record.approval_id,
            session_id=record.session_id,
            capability=record.capability,
            tool=record.tool,
            target=record.target,
            args=record.args,
        )
    assert store.verify(record.approval_id)["valid"] is True


def test_rejection_terminates_without_grant(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "approvals.json", SECRET)
    record = _paused(store)
    terminated = store.reject(record.approval_id, rejected_by="operator-2", trusted_origin="authenticated_user")
    assert terminated.status == "TERMINATED"
    assert [event["event_type"] for event in terminated.events][-2:] == ["REJECTED", "TERMINATED"]
    assert terminated.usage_count == 0


def test_grant_target_args_session_and_signature_are_bound(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "approvals.json", SECRET)
    signer = ApprovalSigner(SECRET)
    record = _paused(store)
    valid = signer.issue(record.binding(), created_by="operator", trusted_origin="trusted_operator")
    forged = replace(valid, target="http://127.0.0.1:8123/other")
    with pytest.raises(PermissionError, match="signature/origin"):
        store.approve(record.approval_id, forged)

    store.approve(record.approval_id, valid)
    with pytest.raises(PermissionError, match="binding mismatch"):
        store.consume(
            record.approval_id,
            session_id="changed-session",
            capability=record.capability,
            tool=record.tool,
            target=record.target,
            args=record.args,
        )


def test_model_or_provider_origin_cannot_forge_approval(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "approvals.json", SECRET)
    signer = ApprovalSigner(SECRET)
    record = _paused(store)
    with pytest.raises(PermissionError, match="not trusted"):
        signer.issue(record.binding(), created_by="contextual-model", trusted_origin="model_provider")

    fake = ApprovalGrant(
        **record.binding().__dict__,
        once=True,
        usage_limit=1,
        expires_at="2999-01-01T00:00:00+00:00",
        created_at="2026-01-01T00:00:00+00:00",
        created_by="contextual-model",
        trusted_origin="trusted_operator",
        nonce="model-controlled",
        signature="0" * 64,
    )
    with pytest.raises(PermissionError, match="signature/origin"):
        store.approve(record.approval_id, fake)


def test_count_limited_grant_tracks_usage_and_expiry(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "approvals.json", SECRET)
    signer = ApprovalSigner(SECRET)
    record = _paused(store)
    grant = signer.issue(
        record.binding(),
        created_by="operator",
        trusted_origin="trusted_operator",
        once=False,
        usage_count=2,
    )
    store.approve(record.approval_id, grant)
    fields = {
        "session_id": record.session_id,
        "capability": record.capability,
        "tool": record.tool,
        "target": record.target,
        "args": record.args,
    }
    assert store.consume(record.approval_id, **fields).usage_count == 1
    assert store.consume(record.approval_id, **fields).usage_count == 2
    with pytest.raises(PermissionError, match="usage limit exhausted"):
        store.consume(record.approval_id, **fields)

    expiring = _paused(store)
    expiring_grant = signer.issue(
        expiring.binding(),
        created_by="operator",
        trusted_origin="trusted_operator",
        ttl_seconds=0.2,
    )
    store.approve(expiring.approval_id, expiring_grant)
    time.sleep(0.3)
    with pytest.raises(PermissionError, match="expired"):
        store.consume(
            expiring.approval_id,
            session_id=expiring.session_id,
            capability=expiring.capability,
            tool=expiring.tool,
            target=expiring.target,
            args=expiring.args,
        )
