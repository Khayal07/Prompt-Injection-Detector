# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Faster, quieter, unbuffered Python in containers.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first so the layer is cached across code changes.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Application code, runtime config, and the gunicorn config.
COPY app ./app
COPY config ./config
COPY docker/gunicorn_conf.py ./gunicorn_conf.py

EXPOSE 8000

# Container-level health check hitting the app's /health endpoint (no curl needed).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health', timeout=4).status==200 else 1)"

# A non-root user for the running service.
RUN useradd --create-home --uid 10001 appuser
USER appuser

# Production server: gunicorn managing uvicorn workers.
CMD ["gunicorn", "app.main:app", "-c", "gunicorn_conf.py"]
