from app.guards import output_guard


def safe_observation_text(observation: str) -> str:
    if not observation.strip():
        return ""
    sanitized = output_guard.sanitize_text(observation)
    if sanitized != observation:
        return sanitized
    return output_guard.safe_refusal_message()


__all__ = [
    "safe_observation_text",
]
