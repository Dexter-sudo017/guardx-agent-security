"""Explicit compatibility adapters for frozen GuardX contracts."""

from app.compat.authorization_vocabulary import (
    AuthorizationVocabularyError,
    canonical_to_r4a,
    r4a_to_canonical,
)

__all__ = ["AuthorizationVocabularyError", "canonical_to_r4a", "r4a_to_canonical"]
