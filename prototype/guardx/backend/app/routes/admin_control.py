from typing import Any

from fastapi import APIRouter

from app.services.control_plane_runtime import control_plane_summary

router = APIRouter()


@router.get("/v1/runtime/control_plane")
def runtime_control_plane() -> dict[str, Any]:
    return control_plane_summary()
