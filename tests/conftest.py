import pytest
from fastapi.testclient import TestClient

from app.infrastructure import memory_store
from app.main import app


@pytest.fixture(autouse=True)
def reset_store():
    memory_store._endpoints.clear()
    memory_store._audit_events.clear()
    memory_store._overrides.clear()
    yield
    memory_store._endpoints.clear()
    memory_store._audit_events.clear()
    memory_store._overrides.clear()


@pytest.fixture()
def client():
    return TestClient(app)
