from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeCanaries:
    values: dict[str, str]

    @classmethod
    def generate(cls) -> "RuntimeCanaries":
        suffix = lambda: secrets.token_urlsafe(24)
        return cls({
            "synthetic_api_key": f"GXAPI_{suffix()}",
            "synthetic_bearer_token": f"GXTOKEN_{suffix()}",
            "synthetic_password": f"GXPASS_{suffix()}",
            "synthetic_env_secret": f"GXENV_{suffix()}",
            "synthetic_personal_identifier": f"GXPII_{suffix()}",
            "synthetic_private_note": f"GXNOTE_{suffix()}",
        })

    def fingerprints(self) -> dict[str, dict[str, object]]:
        return {
            kind: {"sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(), "length": len(value)}
            for kind, value in self.values.items()
        }
