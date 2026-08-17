from app.config import SETTINGS
from app.models import AnalysisResult


def merge_risk(
    input_result: AnalysisResult,
    context_result: AnalysisResult | None,
    session_risk: float,
    embedding_result: AnalysisResult | None = None,
) -> float:
    context_score = context_result.risk_score if context_result else 0.0
    embedding_score = embedding_result.risk_score if embedding_result else 0.0
    weights = SETTINGS.weights
    weighted_score = (
        input_result.risk_score * weights.input_weight
        + context_score * weights.context_weight
        + session_risk * weights.session_weight
        + embedding_score
    )
    # A single strong jailbreak/RAG signal should be enough to trigger policy action.
    score = max(weighted_score, input_result.risk_score, context_score, embedding_score, session_risk * 0.8)
    return min(score, 1.0)


def decide_action(total_risk: float) -> str:
    thresholds = SETTINGS.thresholds
    if total_risk >= thresholds.critical:
        return "terminate"
    if total_risk >= thresholds.high:
        return "block"
    if total_risk >= thresholds.medium:
        return "rewrite"
    return "allow"


def next_session_risk(previous: float, input_risk: float, context_risk: float = 0.0) -> float:
    # Smooth risk update to keep multi-turn signal.
    value = previous * 0.65 + input_risk * 0.25 + context_risk * 0.1
    return min(value, 1.0)
