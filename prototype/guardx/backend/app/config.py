from dataclasses import dataclass
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[4]
THRESHOLD_CONFIG_PATH = PROJECT_ROOT / "configs" / "model_thresholds.json"


def _load_model_config() -> dict:
    if not THRESHOLD_CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(THRESHOLD_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


_CONFIG = _load_model_config()
_THRESHOLDS = _CONFIG.get("thresholds", {})
_WEIGHTS = _CONFIG.get("weights", {})


@dataclass(frozen=True)
class RiskThresholds:
    medium: float = float(_THRESHOLDS.get("medium", 0.45))
    high: float = float(_THRESHOLDS.get("high", 0.7))
    critical: float = float(_THRESHOLDS.get("critical", 0.9))


@dataclass(frozen=True)
class Weights:
    input_weight: float = float(_WEIGHTS.get("input_weight", 0.5))
    context_weight: float = float(_WEIGHTS.get("context_weight", 0.25))
    session_weight: float = float(_WEIGHTS.get("session_weight", 0.25))


@dataclass(frozen=True)
class Settings:
    default_model: str = str(_CONFIG.get("default_model", "mock-safe-model"))
    sqlite_path: str = str(_CONFIG.get("sqlite_path", "data/audit.db"))
    thresholds: RiskThresholds = RiskThresholds()
    weights: Weights = Weights()


SETTINGS = Settings()
