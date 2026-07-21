"""Gunicorn configuration for the production ASGI server.

Runs FastAPI under uvicorn workers. Tunables are environment-driven:
  WEB_CONCURRENCY   number of worker processes (default 2)
  PORT              bind port (default 8000)
  GUNICORN_TIMEOUT  worker timeout in seconds (default 30)
  LOG_LEVEL         gunicorn log level (default info)

Note: the app emits its own structured access log (see app/observability.py), so gunicorn's
access log is disabled to avoid duplicate lines.
"""

import os

bind = f"0.0.0.0:{os.getenv('PORT', '8000')}"
workers = int(os.getenv("WEB_CONCURRENCY", "2"))
worker_class = "uvicorn.workers.UvicornWorker"

timeout = int(os.getenv("GUNICORN_TIMEOUT", "30"))
graceful_timeout = int(os.getenv("GUNICORN_GRACEFUL_TIMEOUT", "30"))
keepalive = int(os.getenv("GUNICORN_KEEPALIVE", "5"))

# App-level middleware handles access logging; keep only gunicorn's error log.
accesslog = None
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info").lower()
