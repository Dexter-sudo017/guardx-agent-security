from typing import Any

from fastapi import APIRouter

from app.eval_presets import list_eval_suites
from app.eval_suite import run_benchmark_suite, run_smoke_suite, runtime_summary
from app.services.admin_runtime import get_app
from app.services.runtime_state import adapter_registry
from app.target_catalog import list_target_catalog
from app.target_profiles import load_target_profiles

router = APIRouter()


@router.get("/v1/eval/smoke")
def eval_smoke() -> dict[str, Any]:
    return run_smoke_suite(get_app())


@router.get("/v1/eval/runtime")
def eval_runtime(model: str | None = None) -> dict[str, Any]:
    return runtime_summary(adapter_registry, model)


@router.get("/v1/eval/suites")
def eval_suites() -> list[dict[str, Any]]:
    return list_eval_suites()


@router.get("/v1/targets/catalog")
def target_catalog() -> list[dict[str, Any]]:
    return list_target_catalog()


@router.get("/v1/targets/profiles")
def target_profiles() -> list[dict[str, Any]]:
    return load_target_profiles()


@router.get("/v1/eval/benchmark")
def eval_benchmark(
    model: str | None = None,
    suite: str | None = None,
    limit: int | None = None,
    case_ids: str | None = None,
) -> dict[str, Any]:
    parsed_case_ids = case_ids.split(",") if case_ids else None
    return run_benchmark_suite(get_app(), adapter_registry, model, suite=suite, case_ids=parsed_case_ids, limit=limit)
