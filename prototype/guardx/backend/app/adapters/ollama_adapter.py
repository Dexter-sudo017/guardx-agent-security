import httpx

from app.adapters.base import ModelAdapter
from app.models import Message


class OllamaAdapter(ModelAdapter):
    def __init__(
        self,
        *,
        base_url: str | None,
        upstream_model: str | None = None,
        temperature: float = 0.2,
        num_predict: int = 192,
        timeout_seconds: float = 45.0,
        think: bool | None = None,
        system_prompt: str | None = None,
    ) -> None:
        self.base_url = (base_url or "http://127.0.0.1:11434").rstrip("/")
        self.upstream_model = upstream_model
        self.temperature = temperature
        self.num_predict = num_predict
        self.timeout_seconds = timeout_seconds
        self.think = think
        self.system_prompt = (system_prompt or "").strip()

    def configured(self) -> bool:
        return bool(self.base_url)

    def generate(self, message: str, history: list[Message], model: str) -> str:
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.extend({"role": item.role, "content": item.content} for item in history)
        messages.append({"role": "user", "content": message})
        payload = {
            "model": self.upstream_model or model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.num_predict,
            },
        }
        if self.think is not None:
            payload["think"] = self.think

        with httpx.Client(timeout=self.timeout_seconds) as client:
            response = client.post(f"{self.base_url}/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()
        message_data = data.get("message", {})
        content = message_data.get("content", "")
        if content:
            return content
        # Some reasoning runtimes can spend the whole budget in `thinking`
        # when `think=false` is unsupported. Do not expose raw reasoning traces.
        if message_data.get("thinking", ""):
            return "The local reasoning model produced no final answer content."
        return ""
