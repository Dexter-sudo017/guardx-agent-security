from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any


_SECRET_KEY = re.compile(r"(?:api[_-]?key|authorization|bearer|password|passwd|access[_-]?token|credential|private[_-]?key|secret|canary)", re.I)
_PATTERNS = [
    re.compile(r"GX(?:API|TOKEN|PASS|ENV|PII|NOTE)_[A-Za-z0-9_-]+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)(?:api[_-]?key|password|access[_-]?token)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
]


@dataclass(frozen=True)
class Redaction:
    classification: str
    sha256: str
    length: int
    path: str


class PersistenceSanitizer:
    def __init__(self, exact_values: dict[str, str] | None = None, *, persist_sensitive: bool = False) -> None:
        self.exact_values = dict(exact_values or {})
        self.persist_sensitive = persist_sensitive

    @staticmethod
    def _summary(value: str, classification: str, path: str) -> Redaction:
        return Redaction(classification, hashlib.sha256(value.encode("utf-8")).hexdigest(), len(value), path)

    def _sanitize_string(self, value: str, path: str, redactions: list[Redaction]) -> str:
        sanitized = value
        for kind, secret in self.exact_values.items():
            if secret and secret in sanitized:
                classification = "SENSITIVE" if kind in {"synthetic_personal_identifier", "synthetic_private_note"} else "SECRET"
                if classification == "SENSITIVE" and self.persist_sensitive:
                    continue
                redactions.append(self._summary(secret, classification, path))
                sanitized = sanitized.replace(secret, f"[REDACTED:{classification}]")
        for pattern in _PATTERNS:
            def replace(match: re.Match[str]) -> str:
                raw = match.group(0)
                redactions.append(self._summary(raw, "SECRET", path))
                return "[REDACTED:SECRET]"
            sanitized = pattern.sub(replace, sanitized)
        return sanitized

    def sanitize_with_report(self, value: Any) -> tuple[Any, list[dict[str, Any]]]:
        redactions: list[Redaction] = []

        def walk(item: Any, path: str) -> Any:
            if isinstance(item, dict):
                result: dict[str, Any] = {}
                for key, child in item.items():
                    child_path = f"{path}.{key}" if path else str(key)
                    if _SECRET_KEY.search(str(key)) and isinstance(child, (str, bytes)):
                        raw = child.decode("utf-8", errors="replace") if isinstance(child, bytes) else child
                        redactions.append(self._summary(raw, "SECRET", child_path))
                        result[str(key)] = "[REDACTED:SECRET]"
                    else:
                        result[str(key)] = walk(child, child_path)
                return result
            if isinstance(item, (list, tuple)):
                return [walk(child, f"{path}[{index}]") for index, child in enumerate(item)]
            if isinstance(item, bytes):
                return self._sanitize_string(item.decode("utf-8", errors="replace"), path, redactions)
            if isinstance(item, str):
                return self._sanitize_string(item, path, redactions)
            if item is None or isinstance(item, (bool, int, float)):
                return item
            return self._sanitize_string(str(item), path, redactions)

        sanitized = walk(value, "")
        return sanitized, [redaction.__dict__ for redaction in redactions]

    def sanitize(self, value: Any) -> Any:
        return self.sanitize_with_report(value)[0]


_DEFAULT_SANITIZER = PersistenceSanitizer()


def sanitize_persistent_payload(value: Any) -> Any:
    return _DEFAULT_SANITIZER.sanitize(value)
