import base64

import pytest

from app.services import live_vlm_ocr


def test_live_vlm_rejects_unsupported_or_invalid_images():
    with pytest.raises(ValueError, match="unsupported image type"):
        live_vlm_ocr._decode_image(base64.b64encode(b"image").decode(), "image/svg+xml")
    with pytest.raises(ValueError, match="valid base64"):
        live_vlm_ocr._decode_image("not-base64", "image/png")


def test_live_vlm_accepts_data_url_and_hashable_bytes():
    payload = base64.b64encode(b"small-image").decode()
    decoded, normalized = live_vlm_ocr._decode_image(f"data:image/png;base64,{payload}", "image/png")
    assert decoded == b"small-image"
    assert normalized == payload


def test_vlm_section_parser_keeps_ocr_caption_and_risk_separate():
    text = "OCR_TEXT:\nInvoice total 88\nVISUAL_CAPTION:\nA receipt\nRISK_SIGNALS:\nNONE"
    assert live_vlm_ocr._section(text, "OCR_TEXT", ("VISUAL_CAPTION", "RISK_SIGNALS")) == "Invoice total 88"
    assert live_vlm_ocr._section(text, "VISUAL_CAPTION", ("RISK_SIGNALS",)) == "A receipt"
