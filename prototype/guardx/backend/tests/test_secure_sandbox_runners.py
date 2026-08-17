import os
import sqlite3
import subprocess
from contextlib import closing
from pathlib import Path

from app.executor_secure.file_runner import SandboxFileRunner
from app.executor_secure.mock_http import local_mock_server
from app.executor_secure.network_runner import LocalHttpRunner
from app.executor_secure.permit import PermitAuthority
from app.executor_secure.runtime import SecureExecutor
from app.executor_secure.sandbox import SandboxRun
from app.executor_secure.sqlite_runner import SandboxSqliteRunner


def _execute(sandbox: SandboxRun, runner, authority: PermitAuthority, capability: str, args: dict):
    return SecureExecutor(authority).execute(
        execution_id=sandbox.execution_id,
        runner=runner,
        capability=capability,
        args=args,
    )


def test_filesystem_read_write_delete_and_path_confinement(tmp_path: Path) -> None:
    sandbox = SandboxRun.create(tmp_path / "runs")
    authority = PermitAuthority(b"permit-test-secret-material-at-least-32-bytes")
    runner = SandboxFileRunner(sandbox, authority)

    write = _execute(
        sandbox,
        runner,
        authority,
        "file_write",
        {"operation": "write", "path": "nested/value.txt", "content": "sandbox-value"},
    )
    assert write.error is None and write.output["state_verified"] is True
    read = _execute(
        sandbox,
        runner,
        authority,
        "file_read",
        {"operation": "read", "path": "nested/value.txt"},
    )
    assert read.output["content"] == "sandbox-value"

    for escaped in ("../outside.txt", str((tmp_path / "absolute.txt").resolve()), "nested/value.txt:secret"):
        denied = _execute(
            sandbox,
            runner,
            authority,
            "file_write",
            {"operation": "write", "path": escaped, "content": "escape"},
        )
        assert denied.precheck_result == "deny"
        assert denied.runner_invocation_count == 0

    delete = _execute(
        sandbox,
        runner,
        authority,
        "file_delete",
        {"operation": "delete", "path": "nested/value.txt"},
    )
    assert delete.output["deleted"] is True
    assert not (sandbox.workspace / "nested/value.txt").exists()


def test_filesystem_symlink_or_junction_escape_is_rejected(tmp_path: Path) -> None:
    sandbox = SandboxRun.create(tmp_path / "runs")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside", encoding="utf-8")
    link = sandbox.workspace / "escape-link"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            raise
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert created.returncode == 0, created.stderr

    authority = PermitAuthority(b"permit-test-secret-material-at-least-32-bytes")
    runner = SandboxFileRunner(sandbox, authority)
    denied = _execute(
        sandbox,
        runner,
        authority,
        "file_write",
        {"operation": "overwrite", "path": "escape-link/secret.txt", "content": "escaped"},
    )
    assert denied.precheck_result == "deny"
    assert denied.runner_invocation_count == 0
    assert (outside / "secret.txt").read_text(encoding="utf-8") == "outside"


def test_sqlite_select_insert_update_delete_transaction_and_rollback(tmp_path: Path) -> None:
    sandbox = SandboxRun.create(tmp_path / "runs")
    authority = PermitAuthority(b"permit-test-secret-material-at-least-32-bytes")
    runner = SandboxSqliteRunner(sandbox, authority)

    insert = _execute(
        sandbox,
        runner,
        authority,
        "database_write",
        {"sql": "INSERT INTO records(id, value) VALUES (?, ?)", "params": [1, "inserted"], "allow_write": True},
    )
    assert insert.output["transaction"] == "committed"
    assert insert.output["state_verified"] is True

    selected = _execute(
        sandbox,
        runner,
        authority,
        "database_read",
        {"sql": "SELECT id, value FROM records", "params": []},
    )
    assert selected.output["rows"] == [[1, "inserted"]]
    assert selected.output["pre_state"]["sha256"] == selected.output["post_state"]["sha256"]

    update = _execute(
        sandbox,
        runner,
        authority,
        "database_write",
        {"sql": "UPDATE records SET value = ? WHERE id = ?", "params": ["updated", 1], "allow_write": True},
    )
    assert update.output["pre_state"]["sha256"] != update.output["post_state"]["sha256"]
    rollback = runner.rollback(sandbox.execution_id)
    assert rollback["restored"] is True
    with closing(sqlite3.connect(runner.db_path)) as connection:
        assert connection.execute("SELECT value FROM records WHERE id = 1").fetchone()[0] == "inserted"

    deleted = _execute(
        sandbox,
        runner,
        authority,
        "database_write",
        {"sql": "DELETE FROM records WHERE id = ?", "params": [1], "allow_write": True},
    )
    assert deleted.output["changed_rows"] == 1
    assert deleted.output["post_state"]["tables"]["records"]["rows"] == []

    cross_table = _execute(
        sandbox,
        runner,
        authority,
        "database_read",
        {"sql": "SELECT * FROM records, sqlite_master", "params": []},
    )
    assert cross_table.error is not None
    assert "sqlite_master" in cross_table.error
    assert "prohibited" in cross_table.error


def test_http_get_post_loopback_only_and_receiver_event_log(tmp_path: Path) -> None:
    sandbox = SandboxRun.create(tmp_path / "runs")
    with local_mock_server(sandbox.root / "network" / "receiver.jsonl") as (server, receiver):
        authority = PermitAuthority(b"permit-test-secret-material-at-least-32-bytes")
        runner = LocalHttpRunner(
            sandbox,
            authority,
            allowed_host="127.0.0.1",
            allowed_port=server.server_port,
            allowed_paths={"/get", "/post"},
        )
        get = _execute(
            sandbox,
            runner,
            authority,
            "network_export",
            {"method": "GET", "url": f"http://localhost:{server.server_port}/get"},
        )
        post = _execute(
            sandbox,
            runner,
            authority,
            "network_export",
            {"method": "POST", "url": f"http://127.0.0.1:{server.server_port}/post", "body": "local-only"},
        )
        public = _execute(
            sandbox,
            runner,
            authority,
            "network_export",
            {"method": "GET", "url": "http://example.com/get"},
        )

        assert get.output["status"] == post.output["status"] == 200
        assert public.precheck_result == "deny"
        assert public.runner_invocation_count == 0
        assert receiver.request_count == 2
        assert [event["method"] for event in receiver.events] == ["GET", "POST"]
        assert [event["body_utf8"] for event in receiver.events] == ["", "local-only"]
        assert (sandbox.root / "network" / "receiver.jsonl").is_file()
