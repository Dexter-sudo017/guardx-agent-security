from functools import lru_cache
from pathlib import Path

import yaml


GUARDX_ROOT = Path(__file__).resolve().parents[2]
TARGET_CONFIG_PATH = GUARDX_ROOT / "configs" / "targets.yaml"


@lru_cache(maxsize=1)
def load_target_profiles() -> list[dict]:
    with TARGET_CONFIG_PATH.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    profiles = payload.get("targets", [])
    return [dict(item) for item in profiles]
