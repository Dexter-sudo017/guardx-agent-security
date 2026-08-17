from __future__ import annotations

import json
import queue
import subprocess
import threading
import time
from pathlib import Path
from typing import Any


class ExternalJsonlWorker:
    def __init__(
        self,
        command: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout_seconds: float,
    ) -> None:
        self.command = command
        self.cwd = cwd
        self.env = env
        self.timeout_seconds = timeout_seconds
        self.process: subprocess.Popen[str] | None = None
        self.responses: queue.Queue[dict[str, Any]] = queue.Queue()
        self.lock = threading.Lock()
        self.reader: threading.Thread | None = None

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            self._ensure_started()
            self._drain_stale_responses()
            assert self.process is not None and self.process.stdin is not None
            request_id = str(payload["request_id"])
            self.process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
            self.process.stdin.flush()
            return self._read_response(request_id)

    def stop(self) -> None:
        process = self.process
        self.process = None
        if process is None:
            return
        try:
            process.terminate()
            process.wait(timeout=2)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass

    def _ensure_started(self) -> None:
        if self.process is not None and self.process.poll() is None:
            return
        self.process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            cwd=str(self.cwd),
            env=self.env,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.reader = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader.start()

    def _reader_loop(self) -> None:
        process = self.process
        if process is None or process.stdout is None:
            return
        for line in process.stdout:
            if not line.strip():
                continue
            try:
                self.responses.put(json.loads(line))
            except Exception as exc:
                self.responses.put({"request_id": None, "ok": False, "error": f"invalid worker json: {exc}"})

    def _drain_stale_responses(self) -> None:
        while True:
            try:
                self.responses.get_nowait()
            except queue.Empty:
                return

    def _read_response(self, request_id: str) -> dict[str, Any]:
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.stop()
                raise TimeoutError("external qwen3 worker timed out")
            try:
                response = self.responses.get(timeout=remaining)
            except queue.Empty:
                self.stop()
                raise TimeoutError("external qwen3 worker timed out")
            if response.get("request_id") == request_id:
                return response
