from typing import Any

from fastapi import APIRouter, Request

from app.services import text_privacy_demo


router = APIRouter()


@router.post("/v1/eval/text_privacy_decoder_demo")
async def run_text_privacy_decoder_demo(raw_request: Request) -> dict[str, Any]:
    payload = await raw_request.json()
    source_text = str(payload.get("source_text") or payload.get("text") or "")
    variant = str(payload.get("variant") or text_privacy_demo.DEFAULT_VARIANT)
    show_reconstruction = bool(payload.get("show_reconstruction", True))
    return text_privacy_demo.run_decoder_demo(source_text, variant=variant, show_reconstruction=show_reconstruction)
