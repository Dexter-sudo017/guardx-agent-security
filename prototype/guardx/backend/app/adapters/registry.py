from pathlib import Path
import time
from typing import Any

import httpx
import yaml

from app.adapters.base import ModelAdapter
from app.adapters.mock_adapter import MockSafeAdapter
from app.adapters.ollama_adapter import OllamaAdapter
from app.adapters.openai_compatible import OpenAICompatibleAdapter, resolve_env
from app.models import ModelInfo


class AdapterRegistry:
    def __init__(self, config_path: str | None = None) -> None:
        self._config_path = Path(config_path) if config_path else Path(__file__).resolve().parents[3] / "configs" / "models.yaml"
        self._config = self._load_config()
        self._ollama_probe_cache: dict[str, tuple[float, set[str]]] = {}

    def _load_config(self) -> dict[str, Any]:
        if not self._config_path.exists():
            return {"models": {"mock-safe-model": {"type": "mock", "description": "fallback mock model"}}}
        return yaml.safe_load(self._config_path.read_text(encoding="utf-8")) or {"models": {}}

    def list_models(self) -> list[ModelInfo]:
        result: list[ModelInfo] = []
        for name, spec in self._config.get("models", {}).items():
            adapter_type = spec.get("type", "unknown")
            configured = self._configured(adapter_type, spec)
            result.append(
                ModelInfo(
                    name=name,
                    adapter_type=adapter_type,
                    description=spec.get("description", ""),
                    configured=configured,
                    upstream_model=spec.get("upstream_model"),
                    capabilities=[str(item) for item in spec.get("capabilities", [])],
                )
            )
        return result

    def get_info(self, model_name: str) -> ModelInfo:
        for item in self.list_models():
            if item.name == model_name:
                return item
        return ModelInfo(name=model_name, adapter_type="unknown", description="not found", configured=False)

    def get_spec(self, model_name: str) -> dict[str, Any]:
        return dict(self._config.get("models", {}).get(model_name) or {})

    def preferred_model_name(self) -> str:
        models = self.list_models()
        for item in models:
            if item.configured and item.adapter_type != "mock":
                return item.name
        return models[0].name if models else "mock-safe-model"

    def _configured(self, adapter_type: str, spec: dict[str, Any]) -> bool:
        if adapter_type == "mock":
            return True
        if adapter_type == "openai_compatible":
            base_url = resolve_env(spec.get("base_url_env")) or spec.get("base_url")
            api_key = resolve_env(spec.get("api_key_env")) or spec.get("api_key")
            return bool(base_url and api_key)
        if adapter_type in {"ollama", "ollama_vlm"}:
            base_url = (spec.get("base_url") or "http://127.0.0.1:11434").rstrip("/")
            try:
                cached = self._ollama_probe_cache.get(base_url)
                if cached and time.monotonic() - cached[0] < 5.0:
                    installed = cached[1]
                else:
                    with httpx.Client(timeout=2.0) as client:
                        response = client.get(f"{base_url}/api/tags")
                        if response.status_code != 200:
                            return False
                        installed = {
                            str(item.get("name") or item.get("model") or "")
                            for item in (response.json().get("models") or [])
                            if isinstance(item, dict)
                        }
                    self._ollama_probe_cache[base_url] = (time.monotonic(), installed)
                upstream_model = str(spec.get("upstream_model") or "").strip()
                return not upstream_model or upstream_model in installed
            except Exception:
                return False
        return False

    def get(self, model_name: str) -> ModelAdapter:
        spec = self._config.get("models", {}).get(model_name)
        if not spec:
            return MockSafeAdapter()

        adapter_type = spec.get("type", "mock")
        if adapter_type == "openai_compatible":
            return OpenAICompatibleAdapter(
                base_url=resolve_env(spec.get("base_url_env")) or spec.get("base_url"),
                api_key=resolve_env(spec.get("api_key_env")) or spec.get("api_key"),
                upstream_model=spec.get("upstream_model"),
                temperature=float(spec.get("temperature", 0.2)),
                max_tokens=int(spec.get("max_tokens", 96)),
            )
        if adapter_type in {"ollama", "ollama_vlm"}:
            return OllamaAdapter(
                base_url=spec.get("base_url"),
                upstream_model=spec.get("upstream_model"),
                temperature=float(spec.get("temperature", 0.2)),
                num_predict=int(spec.get("num_predict", 192)),
                timeout_seconds=float(spec.get("timeout_seconds", 45.0)),
                think=spec.get("think") if "think" in spec else None,
                system_prompt=spec.get("system_prompt"),
            )
        return MockSafeAdapter()
