import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[5]
GENERATION_POLICY_PATH = PROJECT_ROOT / "configs" / "guarded_generation_policy.json"


def load_generation_policy() -> dict:
    if not GENERATION_POLICY_PATH.exists():
        return {"contextual_constraints": [], "adapter_fallback": {"enabled": False}}
    try:
        return json.loads(GENERATION_POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"contextual_constraints": [], "adapter_fallback": {"enabled": False}}


def contextual_constraint_prefix(message: str) -> str:
    lowered = message.lower()
    instructions: list[str] = []
    for rule in load_generation_policy().get("contextual_constraints", []):
        phrases = [str(item).lower() for item in rule.get("match_phrases", [])]
        if phrases and all(phrase in lowered for phrase in phrases):
            instruction = str(rule.get("instruction", "")).strip()
            if instruction:
                instructions.append(instruction)
    return "\n".join(dict.fromkeys(instructions))


def apply_contextual_constraints(message: str, guarded_message: str) -> str:
    prefix = contextual_constraint_prefix(message)
    return f"{prefix}\n\n{guarded_message}" if prefix else guarded_message


def adapter_fallback_models(primary_model: str) -> list[str]:
    fallback = load_generation_policy().get("adapter_fallback", {})
    if not fallback.get("enabled", False):
        return []
    candidates = [str(item) for item in fallback.get("candidate_models", [])]
    max_attempts = int(fallback.get("max_attempts", len(candidates)) or 0)
    return [model for model in candidates if model and model != primary_model][:max_attempts]
