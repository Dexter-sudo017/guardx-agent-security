import os
from typing import Iterable

from app.guards import embedding_guard
from app.models import AnalysisResult, Message


DIRECT_EMBEDDING_ENV = "GUARDX_DIRECT_EMBEDDING_ENABLED"


def _env_enabled(name: str, default: bool = True) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def direct_embedding_enabled() -> bool:
    return _env_enabled(DIRECT_EMBEDDING_ENV, default=True)


def neutral_embedding_analysis(reason: str = "direct_embedding_disabled") -> AnalysisResult:
    return AnalysisResult(
        risk_score=0.0,
        labels=["embedding_disabled"],
        evidence=[reason],
        metadata={"embedding_disabled": True, "reason": reason},
    )


def analyze_direct_embedding(
    message: str,
    history: list[Message],
    context_chunks: Iterable[str] | None = None,
) -> AnalysisResult:
    if not direct_embedding_enabled():
        return neutral_embedding_analysis()
    return embedding_guard.analyze(message, history, list(context_chunks or []))


def embedding_runtime_state() -> dict[str, bool]:
    return {"direct_embedding_enabled": direct_embedding_enabled()}
