"""FastAPI application: the /check firewall endpoint plus health and admin routes.

Built via an app factory (`create_app`) so the service can be constructed from the current
settings — in production from the module-level `app`, and in tests with isolated config.

On startup it builds the detection pipeline (heuristics + classifier) and the database
engine. The service stays usable even if the database is unreachable — logging simply
degrades — so a DB outage never takes the firewall down.

Production concerns (auth, rate limiting, CORS, structured logging, request IDs and
Prometheus metrics) are all configuration-driven and wired up here.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import text

from app.config import get_settings
from app.db.repository import log_detection
from app.db.session import init_db, make_engine, make_session_factory
from app.detector.classifier import LLMClassifier
from app.detector.heuristics import HeuristicEngine
from app.detector.pipeline import DetectionPipeline
from app.observability import RequestContextMiddleware, setup_logging
from app.schemas import CheckRequest, CheckResponse, HealthResponse
from app.security import build_limiter, require_api_key

logger = logging.getLogger("pid.api")

_INDEX_HTML = Path(__file__).resolve().parent / "static" / "index.html"

router = APIRouter()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Build shared, long-lived objects once and attach them to app state."""
    settings = get_settings()
    setup_logging(settings.log_level, settings.json_logs)

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
    logger.info(
        "service ready (auth=%s, rate_limit=%s, classifier=%s, rules=%d)",
        settings.auth_enabled, settings.rate_limit or "off",
        settings.classifier_available, engine.rule_count,
    )

    yield

    db_engine.dispose()


@router.get("/", include_in_schema=False)
def playground() -> FileResponse:
    """Serve a small browser playground for the /check endpoint."""
    return FileResponse(_INDEX_HTML)


@router.post("/check", response_model=CheckResponse, dependencies=[Depends(require_api_key)])
def check(request: Request, payload: CheckRequest, background: BackgroundTasks) -> CheckResponse:
    """Screen a user input and return a risk score, label, and recommended action."""
    state = request.app.state
    settings = state.settings

    if settings.max_input_chars and len(payload.text) > settings.max_input_chars:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"input exceeds max_input_chars ({settings.max_input_chars})",
        )

    # Pick up rule edits without a redeploy/restart when auto-reload is enabled.
    if settings.rules_autoreload:
        state.pipeline.engine.maybe_reload()

    response = state.pipeline.run(payload)

    # Persist off the request path so DB latency never delays the caller.
    background.add_task(
        log_detection, state.session_factory, settings, payload, response
    )
    return response


@router.post("/admin/reload-rules", dependencies=[Depends(require_api_key)])
def reload_rules(request: Request) -> dict:
    """Hot-reload the heuristic rules from disk (no redeploy needed)."""
    try:
        count = request.app.state.pipeline.engine.reload()
    except Exception as exc:  # noqa: BLE001 - surface config errors to the operator
        raise HTTPException(
            status_code=400, detail=f"failed to reload rules: {exc}"
        ) from exc
    return {"status": "reloaded", "rule_count": count}


@router.get("/health", response_model=HealthResponse)
def health(request: Request) -> HealthResponse:
    """Liveness/readiness probe: reports DB connectivity, classifier and rule status."""
    state = request.app.state
    database = "ok"
    try:
        with state.db_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 - health check reports, never raises
        database = "unavailable"

    return HealthResponse(
        status="ok",
        database=database,
        classifier_available=state.settings.classifier_available,
        rules_loaded=state.pipeline.engine.rule_count,
    )


def create_app() -> FastAPI:
    """Application factory: build a FastAPI app from the current settings."""
    settings = get_settings()

    app = FastAPI(
        title="Prompt Injection & Jailbreak Detector",
        description="Real-time firewall that screens LLM inputs for injection and "
        "jailbreak attempts before they reach the model.",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Rate limiting (per client IP, via middleware). RATE_LIMIT="" disables it.
    app.state.limiter = build_limiter()
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # Structured logging + request IDs.
    app.add_middleware(RequestContextMiddleware)

    # CORS (only if configured — needed for cross-origin browser callers).
    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )

    app.include_router(router)

    # Prometheus /metrics.
    if settings.metrics_enabled:
        Instrumentator().instrument(app).expose(app, include_in_schema=False)

    return app


def _safe_url(url: str) -> str:
    """Strip credentials from a DB URL for safe logging."""
    if "@" in url:
        scheme, _, tail = url.partition("://")
        return f"{scheme}://***@{tail.split('@', 1)[-1]}"
    return url


# Module-level app for `uvicorn app.main:app` / gunicorn.
app = create_app()
