import json
from functools import lru_cache
from pathlib import Path

from app.contracts import ExperimentSuiteCase, ExperimentSuiteDefinition, ExperimentSuiteManifest


PROJECT_ROOT = Path(__file__).resolve().parents[5]
EXPERIMENT_SUITES_PATH = PROJECT_ROOT / "configs" / "experiment_suites.json"


def _empty_manifest() -> ExperimentSuiteManifest:
    return ExperimentSuiteManifest(suites={"guardx_builtin_smoke": ExperimentSuiteDefinition(cases=[])})


@lru_cache(maxsize=1)
def load_experiment_suites() -> ExperimentSuiteManifest:
    if not EXPERIMENT_SUITES_PATH.exists():
        return _empty_manifest()
    try:
        raw = json.loads(EXPERIMENT_SUITES_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _empty_manifest()
    return ExperimentSuiteManifest.model_validate(raw)


def experiment_suite_cases(suite_id: str) -> list[ExperimentSuiteCase]:
    manifest = load_experiment_suites()
    suite = manifest.suites.get(suite_id) or manifest.suites.get(manifest.default_suite)
    return list(suite.cases) if suite else []
