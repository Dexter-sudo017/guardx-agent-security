from __future__ import annotations

import hashlib
import http.client
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from app.executor_secure.models import PrecheckDecision
from app.executor_secure.permit import ExecutionPermit, PermitAuthority
from app.executor_secure.runner_base import PermitProtectedRunner
from app.executor_secure.sandbox import SandboxRun


_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1"})


class LocalHttpRunner(PermitProtectedRunner):
    runner_id = "local_http_runner"

    def __init__(
        self,
        sandbox: SandboxRun,
        authority: PermitAuthority,
        *,
        allowed_host: str,
        allowed_port: int,
        allowed_paths: set[str],
        event_log_path: Path | None = None,
    ) -> None:
        super().__init__(authority)
        self.sandbox = sandbox
        normalized_host = allowed_host.strip().lower()
        if normalized_host not in _LOCAL_HOSTS:
            raise ValueError("HTTP sandbox can only be configured for localhost/127.0.0.1")
        self.allowed_hosts = _LOCAL_HOSTS
        self.allowed_port = int(allowed_port)
        if not (1 <= self.allowed_port <= 65535):
            raise ValueError("invalid localhost receiver port")
        self.allowed_paths = set(allowed_paths)
        default_log = sandbox.root / "network" / "executor_events.jsonl"
        self.event_log_path = (event_log_path or default_log).resolve()
        if self.event_log_path.parent != (sandbox.root / "network").resolve():
            raise ValueError("HTTP event log must remain inside disposable sandbox")
        self.events: list[dict[str, Any]] = []
        self._event_lock = threading.Lock()

    def capability_precheck(self, capability: str, args: dict[str, Any]) -> bool:
        return capability in {"local.http.request", "network_export"}

    def approval_target(self, args: dict[str, Any]) -> str:
        return str(args.get("url", ""))

    def _validate_url(self, url: str, *, require_path_allowlist: bool = True) -> tuple[str, int, str]:
        parsed = urlsplit(url)
        if parsed.scheme != "http" or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("URL scheme/userinfo/fragment rejected")
        host = (parsed.hostname or "").lower()
        try:
            port = parsed.port or 80
        except ValueError as exc:
            raise ValueError("invalid URL port") from exc
        path = parsed.path or "/"
        if host not in self.allowed_hosts or port != self.allowed_port:
            raise ValueError("public or non-allowlisted host/port rejected")
        if require_path_allowlist and path not in self.allowed_paths:
            raise ValueError("path is not allowlisted")
        if any(ord(character) < 32 for character in path + parsed.query):
            raise ValueError("control character in HTTP target rejected")
        return host, port, path + (("?" + parsed.query) if parsed.query else "")

    def normalize_and_precheck(self, args: dict[str, Any]) -> PrecheckDecision:
        method = str(args.get("method", "GET")).upper()
        url = str(args.get("url", "")).strip()
        body = str(args.get("body", ""))
        normalized = {"method": method, "url": url, "body": body}
        if method not in {"GET", "POST"}:
            return PrecheckDecision(False, "HTTP method rejected", normalized)
        if method == "GET" and body:
            return PrecheckDecision(False, "GET request body rejected", normalized)
        if any(token in body for token in ("GXAPI_", "GXTOKEN_", "GXPASS_", "GXENV_", "GXPII_", "GXNOTE_")):
            return PrecheckDecision(False, "sensitive request body rejected", normalized)
        try:
            self._validate_url(url)
        except (TypeError, ValueError) as exc:
            return PrecheckDecision(False, str(exc), normalized)
        return PrecheckDecision(True, "localhost endpoint allowlisted without DNS resolution", normalized)

    def _record_event(self, event: dict[str, Any]) -> None:
        with self._event_lock:
            self.events.append(event)
            if self.event_log_path is not None:
                self.event_log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.event_log_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")

    def run(self, *, execution_id: str, capability: str, args: dict[str, Any], permit: ExecutionPermit) -> dict[str, Any]:
        if execution_id != self.sandbox.execution_id:
            raise PermissionError("execution_id is not bound to this disposable sandbox")
        permit_hash = self._consume(permit, execution_id=execution_id, capability=capability, args=args)
        host, port, target = self._validate_url(str(args["url"]))
        body = str(args.get("body", "")).encode("utf-8")
        # Always connect to the numeric loopback address. "localhost" is accepted
        # as an input spelling but is never resolved through DNS.
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2.0)
        try:
            conn.request(str(args["method"]), target, body=body or None, headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            payload = response.read()
            if 300 <= response.status < 400:
                location = response.getheader("Location") or ""
                self._validate_url(urljoin(str(args["url"]), location))
                raise PermissionError("redirects are not followed")
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "execution_id": execution_id,
                "method": str(args["method"]),
                "url": str(args["url"]),
                "connected_address": "127.0.0.1",
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "status": response.status,
                "permit_hash": permit_hash,
            }
            self._record_event(event)
            return {
                "status": response.status,
                "response_sha256": hashlib.sha256(payload).hexdigest(),
                "response_length": len(payload),
                "event_index": len(self.events) - 1,
                "permit_hash": permit_hash,
            }
        finally:
            conn.close()

    def rollback(self, execution_id: str) -> dict[str, Any]:
        return {"rollback_performed": False, "restored": False, "failure_reason": "network actions are not reversible"}

    def state_hash(self) -> str:
        raw = json.dumps(self.events, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()
