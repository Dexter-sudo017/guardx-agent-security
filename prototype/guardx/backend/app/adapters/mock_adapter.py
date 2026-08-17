from app.adapters.base import ModelAdapter
from app.models import Message


class MockSafeAdapter(ModelAdapter):
    """A deterministic local adapter so the prototype runs without external API keys."""

    def generate(self, message: str, history: list[Message], model: str) -> str:
        lower = message.lower()
        if "summary" in lower:
            return "Summary: this looks like a normal request and can be answered safely."
        if "code" in lower:
            return "I can provide safe code guidance if the request stays within policy."
        return (
            "GuardX mock model response. "
            "This adapter is local-only and intended for safety workflow testing."
        )

