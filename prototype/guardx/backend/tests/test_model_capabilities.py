from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest

from app.adapters.registry import AdapterRegistry
from app.services import live_vlm_ocr


def test_registry_separates_text_and_vision_capabilities(monkeypatch):
    registry = AdapterRegistry()
    monkeypatch.setattr(registry, "_configured", lambda _adapter_type, _spec: True)

    text = registry.get_info("local-ollama-qwen2_5-7b")
    local_vlm = registry.get_info("local-ollama-qwen2_5-vl-7b")
    api_vlm = registry.get_info("dashscope-qwen-vl-plus")

    assert "chat" in text.capabilities
    assert "vision" not in text.capabilities
    assert local_vlm.adapter_type == "ollama_vlm"
    assert local_vlm.capabilities == ["vision", "ocr"]
    assert api_vlm.capabilities == ["vision", "ocr"]


def test_registered_vlm_rejects_text_only_model():
    registry = SimpleNamespace(
        get_info=lambda _name: SimpleNamespace(capabilities=["chat"], configured=True, adapter_type="ollama"),
        get_spec=lambda _name: {},
    )
    with pytest.raises(ValueError, match="not registered for vision"):
        live_vlm_ocr.analyze_image_with_registered_vlm(
            image_base64=base64.b64encode(b"image").decode("ascii"),
            mime_type="image/png",
            user_prompt="读取图片",
            model_name="local-text-model",
            registry=registry,
        )


def test_registered_api_vlm_uses_multimodal_message(monkeypatch):
    captured = {}

    class _Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": "OCR_TEXT:\n发票金额 100 元\nVISUAL_CAPTION:\n一张发票\nRISK_SIGNALS:\nNONE"
                        }
                    }
                ]
            }

    class _Client:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, url, *, headers, json):
            captured.update(url=url, headers=headers, json=json)
            return _Response()

    registry = SimpleNamespace(
        get_info=lambda _name: SimpleNamespace(capabilities=["vision", "ocr"], configured=True, adapter_type="openai_compatible"),
        get_spec=lambda _name: {
            "base_url": "https://dashscope.example.invalid/v1",
            "api_key": "test-only-key",
            "upstream_model": "qwen-vl-plus",
            "max_tokens": 512,
        },
    )
    monkeypatch.setattr(live_vlm_ocr.httpx, "Client", _Client)
    result = live_vlm_ocr.analyze_image_with_registered_vlm(
        image_base64=base64.b64encode(b"image-bytes").decode("ascii"),
        mime_type="image/png",
        user_prompt="提取发票金额",
        model_name="dashscope-qwen-vl-plus",
        registry=registry,
    )

    content = captured["json"]["messages"][0]["content"]
    assert captured["url"].endswith("/chat/completions")
    assert content[0]["type"] == "text"
    assert content[1]["type"] == "image_url"
    assert result["provider_mode"] == "real-api-vlm"
    assert result["ocr_text"] == "发票金额 100 元"
    assert result["registry_model"] == "dashscope-qwen-vl-plus"
