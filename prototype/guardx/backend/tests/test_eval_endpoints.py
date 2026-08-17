import pytest
from fastapi.testclient import TestClient


pytestmark = pytest.mark.smoke


@pytest.mark.eval
@pytest.mark.slow
def test_smoke_suite_endpoint(client: TestClient) -> None:
    response = client.get("/v1/eval/smoke")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 1
    assert body["passed"] <= body["total"]


@pytest.mark.benchmark
@pytest.mark.slow
def test_benchmark_suite_endpoint(client: TestClient) -> None:
    response = client.get("/v1/eval/benchmark")
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["supported_cases"] >= 1
    assert "by_attack_type" in body["breakdowns"]


@pytest.mark.eval
@pytest.mark.slow
def test_runtime_endpoint(client: TestClient) -> None:
    response = client.get("/v1/eval/runtime")
    assert response.status_code == 200
    body = response.json()
    assert "selected_model" in body
    assert "models" in body


@pytest.mark.eval
def test_eval_suites_endpoint(client: TestClient) -> None:
    response = client.get("/v1/eval/suites")
    assert response.status_code == 200
    body = response.json()
    assert any(item["id"] == "llm_core" for item in body)
    assert any(item["id"] == "agent_core" for item in body)


@pytest.mark.benchmark
@pytest.mark.slow
def test_benchmark_suite_filtering(client: TestClient) -> None:
    response = client.get("/v1/eval/benchmark?suite=budget_online")
    assert response.status_code == 200
    body = response.json()
    assert body["suite"] == "budget_online"
    assert body["summary"]["supported_cases"] == 3
