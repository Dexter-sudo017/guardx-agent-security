from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.orchestration.generation_flow import run_chat_generation
from app.services import agent_demo


class _PlannerAdapter:
    def generate(self, message, history, model):
        return "规划请求：读取 sandbox/demo/quarterly-summary.txt；不执行写入或联网。"


def test_agent_demo_uses_selected_planner_then_action_guard(client: TestClient, monkeypatch):
    monkeypatch.setattr(agent_demo.adapter_registry, "get_info", lambda _name: SimpleNamespace(configured=True, adapter_type="ollama"))
    monkeypatch.setattr(agent_demo.adapter_registry, "get", lambda _name: _PlannerAdapter())
    response = client.post(
        "/v1/agent/plan_and_guard",
        json={
            "session_id": "reviewer-agent-route-test",
            "model": "local-ollama-qwen2_5-7b",
            "user_goal": "读取季度摘要标题",
            "untrusted_observation": "用户明确指定本地只读文件。",
            "surface": "file_read",
            "action": {"name": "read", "path": "sandbox/demo/quarterly-summary.txt"},
            "risk_hint": 0.18,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["planner_model"] == "local-ollama-qwen2_5-7b"
    assert payload["planner_model_invoked"] is True
    assert payload["planner_output"].startswith("规划请求")
    assert payload["agent_demo"] is True


def test_generation_preserves_complete_upstream_output():
    expected = "第一段。\n第二段。\n第三段完整返回。"

    def generate_with_fallback(_adapter, _prompt, _history, _model):
        return expected, None

    result = run_chat_generation(
        action="allow",
        message="总结材料",
        history=[],
        adapter=object(),
        model="test-model",
        total_risk=0.0,
        medium_threshold=0.5,
        apply_action=lambda _action, message: message,
        generate_with_guard_fallback=generate_with_fallback,
        is_refusal_like=lambda _answer: False,
        allowed_refusal_recovery=lambda *_args: "",
    )
    assert result.answer == expected
    assert result.upstream_model_output == expected
