import os
import json

import httpx

from app.adapters.base import ModelAdapter
from app.models import Message


class OpenAICompatibleAdapter(ModelAdapter):
    def __init__(
        self,
        *,
        base_url: str | None,
        api_key: str | None,
        upstream_model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 96,
    ) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.api_key = api_key
        self.upstream_model = upstream_model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    def _content_from_stream_text(self, text: str) -> str:
        parts: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            payload = line.removeprefix("data:").strip()
            if payload == "[DONE]":
                continue
            try:
                chunk = json.loads(payload)
            except ValueError:
                continue
            for choice in chunk.get("choices", []):
                delta = choice.get("delta") or choice.get("message") or {}
                content = delta.get("content")
                if content:
                    parts.append(str(content))
        if parts:
            return "".join(parts)
        return "The upstream streaming model produced no final answer content."

    def generate(self, message: str, history: list[Message], model: str) -> str:
        if not self.configured():
            return (
                "GuardX could not reach the upstream OpenAI-compatible model because "
                "the base URL or API key is not configured."
            )

        messages = [{"role": item.role, "content": item.content} for item in history]
        messages.append({"role": "user", "content": message})
        payload = {
            "model": self.upstream_model or model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}

        with httpx.Client(timeout=90.0) as client:
            response = client.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
            response.raise_for_status()
            if "text/event-stream" in response.headers.get("content-type", ""):
                return self._content_from_stream_text(response.text)
            data = response.json()
        message_data = data["choices"][0].get("message", {})
        content = message_data.get("content", "")
        if content:
            return content
        if message_data.get("reasoning_content"):
            return "The upstream reasoning model produced no final answer content."
        return ""


def resolve_env(name: str | None) -> str | None:
    if not name:
        return None
    return os.getenv(name)
