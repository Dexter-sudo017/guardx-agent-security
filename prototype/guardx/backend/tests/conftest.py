from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="session")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def session_id(request: pytest.FixtureRequest) -> str:
    return f"{request.node.name}-{uuid4().hex[:8]}"
