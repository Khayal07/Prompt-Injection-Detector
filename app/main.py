"""FastAPI application: the /check firewall endpoint plus health and admin routes.

On startup it builds the detection pipeline (heuristics + classifier) and the database
engine. The service stays usable even if the database is unreachable — logging simply
degrades — so a DB outage never takes the firewall down.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import text

from app.config import get_settings
from app.db.repository import log_detection
from app.db.session import init_db, make_engine, make_session_factory
from app.detector.classifier import LLMClassifier
from app.detector.heuristics import HeuristicEngine
from app.detector.pipeline import DetectionPipeline
from app.schemas import CheckRequest, CheckResponse, HealthResponse

logger = logging.getLogger("pid.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Build shared, long-lived objects once and attach them to app state."""
    settings = get_settings()

    engine = HeuristicEngine(settings.rules_path)
    classifier = LLMClassifier(settings)
    pipeline = DetectionPipeline(settings, engine, classifier)

    db_engine = make_engine(settings.database_url)
    session_factory = make_session_factory(db_engine)
    try:
        init_db(db_engine)
        logger.info("database initialised at %s", _safe_url(settings.database_url))
    except Exception as exc:  # noqa: BLE001 - service runs without logging if DB is down
        logger.warning("database unavailable, logging disabled at startup: %s", exc)

    app.state.settings = settings
    app.state.pipeline = pipeline
    app.state.db_engine = db_engine
    app.state.session_factory = session_factory

    yield

    db_engine.dispose()


app = FastAPI(
    title="Prompt Injection & Jailbreak Detector",
    description="Real-time firewall that screens LLM inputs for injection and jailbreak "
    "attempts before they reach the model.",
    version="0.1.0",
    lifespan=lifespan,
)


_INDEX_HTML = Path(__file__).resolve().parent / "static" / "index.html"


@app.get("/", include_in_schema=False)
def playground() -> FileResponse:
    """Serve a small browser playground for the /check endpoint."""
    return FileResponse(_INDEX_HTML)


@app.post("/check", response_model=CheckResponse)
def check(request: CheckRequest, background: BackgroundTasks) -> CheckResponse:
    """Screen a user input and return a risk score, label, and recommended action."""
    settings = app.state.settings
    response = app.state.pipeline.run(request)

    # Persist off the request path so DB latency never delays the caller.
    background.add_task(
        log_detection,
        app.state.session_factory,
        settings,
        request,
        response,
    )
    return response


@app.post("/admin/reload-rules")
def reload_rules() -> dict:
    """Hot-reload the heuristic rules from disk (no redeploy needed)."""
    try:
        count = app.state.pipeline.engine.reload()
    except Exception as exc:  # noqa: BLE001 - surface config errors to the operator
        raise HTTPException(status_code=400, detail=f"failed to reload rules: {exc}")
    return {"status": "reloaded", "rule_count": count}


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness/readiness probe: reports DB connectivity, classifier and rule status."""
    settings = app.state.settings
    database = "ok"
    try:
        with app.state.db_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 - health check reports, never raises
        database = "unavailable"

    return HealthResponse(
        status="ok",
        database=database,
        classifier_available=settings.classifier_available,
        rules_loaded=app.state.pipeline.engine.rule_count,
    )


def _safe_url(url: str) -> str:
    """Strip credentials from a DB URL for safe logging."""
    if "@" in url:
        scheme, _, tail = url.partition("://")
        return f"{scheme}://***@{tail.split('@', 1)[-1]}"
    return url
