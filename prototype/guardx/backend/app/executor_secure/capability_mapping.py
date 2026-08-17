from typing import Final


CAPABILITY_RUNNERS: Final[dict[str, str]] = {
    "file_read": "sandbox_file_runner",
    "file_write": "sandbox_file_runner",
    "file_delete": "sandbox_file_runner",
    "database_read": "sandbox_sqlite_runner",
    "database_write": "sandbox_sqlite_runner",
    "network_export": "local_http_runner",
}
