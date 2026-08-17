import json
from time import perf_counter
from typing import Any
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

from app.contracts import PluginManifest, PluginStatus, RiskFinding
from app.guards import embedding_guard
from app.risk_providers import RiskProviderRequest, RiskSegment, finding_from_analysis, finding_from_score


class InProcessSrtpEmbedGuardProvider:
    provider_id = "srtp_embedguard"

    def score(self, request: RiskProviderRequest, segments: list[RiskSegment]) -> list[RiskFinding]:
        started = perf_counter()
        message_parts = [segment.text for segment in segments if segment.trust_boundary.source == "user"]
        context_chunks = [segment.text for segment in segments if segment.trust_boundary.source != "user"]
        message = "\n".join(message_parts) if message_parts else "\n".join(segment.text for segment in segments)
        analysis = embedding_guard.analyze(message, [], context_chunks)
        finding = finding_from_analysis(
            self.provider_id,
            request.surface,
            analysis,
            risk_type="prompt_injection",
            latency_ms=round((perf_counter() - started) * 1000.0, 3),
        )
        finding.features["segments"] = [segment.model_dump() for segment in segments]
        finding.features["deployment_mode"] = "in_process"
        return [finding]

    def health(self) -> PluginStatus:
        started = perf_counter()
        status = embedding_guard.embedding_backend_status()
        return PluginStatus(
            provider_id=self.provider_id,
            status="ok" if status.get("available") else "degraded",
            deployment_mode="in_process",
            message=str(status.get("reason", "")),
            latency_ms=round((perf_counter() - started) * 1000.0, 3),
        )

    def metadata(self) -> PluginManifest:
        policy = embedding_guard.load_policy()
        model = embedding_guard.load_model()
        return PluginManifest(
            provider_id=self.provider_id,
            name="SRTP EmbedGuard",
            version=str(policy.get("schema_version", "unknown")),
            deployment_modes=["in_process", "sidecar_service"],
            capabilities=["score", "health", "metadata"],
            model_versions={
                "policy": str(policy.get("schema_version", "unknown")),
                "model": str(model.get("schema_version", "unknown")),
            },
            config={
                "embedding_backend": policy.get("embedding_backend", {}),
                "embedding_dim": policy.get("embedding_dim"),
                "risk_weight": policy.get("risk_weight"),
            },
        )


class SidecarSrtpEmbedGuardProvider:
    provider_id = "srtp_embedguard"

    def __init__(self, base_url: str, timeout_seconds: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = int(timeout_seconds)

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib_request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib_request.urlopen(request, timeout=self.timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))

    def _get(self, path: str) -> dict[str, Any]:
        with urllib_request.urlopen(f"{self.base_url}{path}", timeout=self.timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))

    def score(self, request: RiskProviderRequest, segments: list[RiskSegment]) -> list[RiskFinding]:
        started = perf_counter()
        try:
            payload = {
                "request": request.model_dump(),
                "segments": [segment.model_dump() for segment in segments],
            }
            response = self._post("/score", payload)
            findings = response.get("risk_findings", [])
            return [RiskFinding.model_validate(item) for item in findings]
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            return [
                finding_from_score(
                    provider_id=self.provider_id,
                    surface=request.surface,
                    risk_score=0.0,
                    risk_type="prompt_injection",
                    confidence=0.0,
                    evidence_refs=[f"sidecar_unavailable:{type(exc).__name__}"],
                    features={
                        "deployment_mode": "sidecar_service",
                        "base_url": self.base_url,
                    },
                    latency_ms=round((perf_counter() - started) * 1000.0, 3),
                )
            ]

    def health(self) -> PluginStatus:
        started = perf_counter()
        try:
            response = self._get("/health")
            status = str(response.get("status") or "ok")
            message = str(response.get("message") or "")
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            status = "unavailable"
            message = f"{type(exc).__name__}: {exc}"
        return PluginStatus(
            provider_id=self.provider_id,
            status=status if status in {"ok", "degraded", "unavailable"} else "degraded",
            deployment_mode="sidecar_service",
            message=message,
            latency_ms=round((perf_counter() - started) * 1000.0, 3),
        )

    def metadata(self) -> PluginManifest:
        try:
            response = self._get("/metadata")
            return PluginManifest.model_validate(response)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError):
            return PluginManifest(
                provider_id=self.provider_id,
                name="SRTP EmbedGuard Sidecar",
                version="unknown",
                deployment_modes=["sidecar_service"],
                capabilities=["score", "health", "metadata"],
                config={"base_url": self.base_url},
            )


def make_srtp_embedguard_provider(mode: str = "in_process", *, base_url: str = "", timeout_seconds: int = 30):
    normalized = mode.strip().lower()
    if normalized == "sidecar_service":
        return SidecarSrtpEmbedGuardProvider(base_url=base_url, timeout_seconds=timeout_seconds)
    return InProcessSrtpEmbedGuardProvider()
