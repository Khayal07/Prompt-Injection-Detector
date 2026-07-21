"""Integration tests for production features: auth, input limits, request IDs, metrics.

Each test builds an isolated app via the factory with a specific environment, so config
that is read at construction time (auth, CORS, metrics, rate limit) is exercised correctly.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient


def _make_client(tmp_path, **env) -> TestClient:
    base = {
        "DATABASE_URL": f"sqlite:///{tmp_path / 'prod.db'}",
        "CLASSIFIER_ENABLED": "false",
        "OPENAI_API_KEY": "",
        "OPENROUTER_API_KEY": "",
        "RATE_LIMIT": "",
        "API_KEYS": "",
        "JSON_LOGS": "false",
        "METRICS_ENABLED": "false",
    }
    base.update(env)
    os.environ.update({k: str(v) for k, v in base.items()})

    from app.config import get_settings

    get_settings.cache_clear()
    from app.main import create_app

    return TestClient(create_app())


@pytest.fixture
def auth_client(tmp_path) -> Iterator[TestClient]:
    with _make_client(tmp_path, API_KEYS="secret-key-1,secret-key-2") as c:
        yield c
    from app.config import get_settings

    get_settings.cache_clear()


# --- Auth --------------------------------------------------------------------


def test_check_requires_key_when_auth_enabled(auth_client):
    resp = auth_client.post("/check", json={"text": "hello"})
    assert resp.status_code == 401


def test_check_accepts_valid_key(auth_client):
    resp = auth_client.post(
        "/check", json={"text": "What is the capital of France?"},
        headers={"X-API-Key": "secret-key-1"},
    )
    assert resp.status_code == 200
    assert resp.json()["label"] == "benign"


def test_check_rejects_wrong_key(auth_client):
    resp = auth_client.post(
        "/check", json={"text": "hello"}, headers={"X-API-Key": "nope"}
    )
    assert resp.status_code == 401


def test_admin_requires_key(auth_client):
    assert auth_client.post("/admin/reload-rules").status_code == 401
    ok = auth_client.post("/admin/reload-rules", headers={"X-API-Key": "secret-key-2"})
    assert ok.status_code == 200


def test_health_is_public_even_with_auth(auth_client):
    assert auth_client.get("/health").status_code == 200


# --- Input limits ------------------------------------------------------------


def test_oversized_input_is_rejected(tmp_path):
    with _make_client(tmp_path, MAX_INPUT_CHARS="50") as c:
        resp = c.post("/check", json={"text": "x" * 100})
        assert resp.status_code == 413
    from app.config import get_settings

    get_settings.cache_clear()


# --- Request ID --------------------------------------------------------------


def test_request_id_header_present(tmp_path):
    with _make_client(tmp_path) as c:
        resp = c.post("/check", json={"text": "hello"})
        assert resp.headers.get("X-Request-ID")
    from app.config import get_settings

    get_settings.cache_clear()


def test_request_id_is_propagated(tmp_path):
    with _make_client(tmp_path) as c:
        resp = c.post("/check", json={"text": "hello"},
                      headers={"X-Request-ID": "trace-abc-123"})
        assert resp.headers.get("X-Request-ID") == "trace-abc-123"
    from app.config import get_settings

    get_settings.cache_clear()


# --- Rate limiting -----------------------------------------------------------


def test_rate_limit_returns_429(tmp_path):
    with _make_client(tmp_path, RATE_LIMIT="3/minute") as c:
        codes = [c.post("/check", json={"text": "hi"}).status_code for _ in range(5)]
        assert 429 in codes
        assert codes.count(200) <= 3
    from app.config import get_settings

    get_settings.cache_clear()


# --- Metrics -----------------------------------------------------------------


def test_metrics_endpoint(tmp_path):
    with _make_client(tmp_path, METRICS_ENABLED="true") as c:
        c.post("/check", json={"text": "hello"})
        resp = c.get("/metrics")
        assert resp.status_code == 200
        assert "http_request" in resp.text
    from app.config import get_settings

    get_settings.cache_clear()
