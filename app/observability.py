"""Structured logging and per-request context (request IDs).

Emits one structured log line per request with method, path, status, duration and a
request id that is also returned in the `X-Request-ID` response header. Set `JSON_LOGS`
false for human-readable local logs.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Holds the current request id so any log record within the request can include it.
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")


class RequestIdFilter(logging.Filter):
    """Injects the current request id into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx.get()
        return True


class JsonFormatter(logging.Formatter):
    """Minimal JSON log formatter (no external dependency)."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "request_id": getattr(record, "request_id", "-"),
            "message": record.getMessage(),
        }
        # Merge any structured extras attached via `logger.info(..., extra={"extra": {...}})`.
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: str, json_logs: bool) -> None:
    """Configure root logging once, with the request-id filter on the handler."""
    handler = logging.StreamHandler()
    handler.addFilter(RequestIdFilter())
    if json_logs:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s [%(request_id)s] %(name)s: %(message)s")
        )

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a request id, times the request, and logs a structured access line."""

    def __init__(self, app, logger_name: str = "pid.access"):
        super().__init__(app)
        self._logger = logging.getLogger(logger_name)

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        token = request_id_ctx.set(request_id)
        start = time.perf_counter()
        # Log inside the context (before the finally reset) so the request id is captured.
        try:
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start) * 1000.0
            response.headers["X-Request-ID"] = request_id
            self._logger.info(
                "request",
                extra={"extra": {"method": request.method,
                                 "path": request.url.path,
                                 "status": response.status_code,
                                 "duration_ms": round(duration_ms, 2)}},
            )
            return response
        except Exception:
            duration_ms = (time.perf_counter() - start) * 1000.0
            self._logger.exception(
                "request failed",
                extra={"extra": {"method": request.method,
                                 "path": request.url.path,
                                 "duration_ms": round(duration_ms, 2)}},
            )
            raise
        finally:
            request_id_ctx.reset(token)
