"""Fixtures for integration tests.

Runs the real FastAPI app against a throwaway SQLite database with the LLM classifier
disabled, so the tests exercise the full request path (including logging) without any
network calls or a running Postgres.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client(tmp_path_factory) -> Iterator[TestClient]:
    db_path = tmp_path_factory.mktemp("db") / "test.db"
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["CLASSIFIER_ENABLED"] = "false"
    os.environ["OPENAI_API_KEY"] = ""
    os.environ["OPENROUTER_API_KEY"] = ""
    os.environ["RATE_LIMIT"] = ""          # disable rate limiting for the default client
    os.environ["API_KEYS"] = ""            # auth disabled by default
    os.environ["JSON_LOGS"] = "false"
    os.environ["METRICS_ENABLED"] = "false"

    # Settings are cached; clear so the app picks up the test environment above.
    from app.config import get_settings

    get_settings.cache_clear()

    from app.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client

    get_settings.cache_clear()
