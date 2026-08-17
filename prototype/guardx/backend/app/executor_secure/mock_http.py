from __future__ import annotations

import hashlib
import json
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator


class LocalMockReceiver:
    """Loopback-only receiver owned by a disposable integration-test fixture."""

    def __init__(self, event_log_path: Path | None = None) -> None:
        self.event_log_path = event_log_path.resolve() if event_log_path else None
        self.events: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def _respond(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else b""
                event = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "method": self.command,
                    "path": self.path,
                    "client_address": self.client_address[0],
                    "content_type": self.headers.get("Content-Type"),
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                    "body_utf8": body.decode("utf-8", errors="replace"),
                }
                with receiver._lock:
                    event["sequence"] = len(receiver.events)
                    receiver.events.append(event)
                    if receiver.event_log_path is not None:
                        receiver.event_log_path.parent.mkdir(parents=True, exist_ok=True)
                        with receiver.event_log_path.open("a", encoding="utf-8") as handle:
                            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
                if self.path == "/redirect-external":
                    self.send_response(302)
                    self.send_header("Location", "http://example.com/exfil")
                    self.end_headers()
                    return
                payload = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = _respond
            do_POST = _respond

            def log_message(self, format: str, *args: object) -> None:
                return

        self._handler = Handler
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True, name="guardx-local-mock")
        self._started = False

    @property
    def port(self) -> int:
        return int(self.server.server_port)

    @property
    def request_count(self) -> int:
        with self._lock:
            return len(self.events)

    @property
    def bodies(self) -> list[bytes]:
        with self._lock:
            return [event["body_utf8"].encode("utf-8") for event in self.events]

    def start(self) -> "LocalMockReceiver":
        if not self._started:
            self._thread.start()
            self._started = True
        return self

    def stop(self) -> None:
        if self._started:
            self.server.shutdown()
            self.server.server_close()
            self._thread.join(timeout=2)
            self._started = False


@contextmanager
def local_mock_server(event_log_path: Path | None = None) -> Iterator[tuple[ThreadingHTTPServer, LocalMockReceiver]]:
    receiver = LocalMockReceiver(event_log_path).start()
    try:
        yield receiver.server, receiver
    finally:
        # This only stops the fixture-owned disposable receiver. It never probes,
        # closes, or otherwise touches pre-existing localhost services.
        receiver.stop()
