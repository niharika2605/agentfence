from fastapi.testclient import TestClient

from agentfence.main import app

client = TestClient(app)


def test_healthz() -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_readyz_is_fail_closed_by_default() -> None:
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json()["fail_closed"] is True