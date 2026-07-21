"""API authentication and rate limiting.

Both are opt-in and driven by configuration so local development stays frictionless:
- Auth activates only when `API_KEYS` is set; requests must then carry a matching
  `X-API-Key` header.
- Rate limiting uses slowapi keyed by client address; set `RATE_LIMIT` empty to disable.
"""

from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import get_settings


def build_limiter() -> Limiter:
    """Construct the slowapi limiter from settings.

    The limit is applied as a default limit (per client IP, via SlowAPIMiddleware) across
    all routes. An empty RATE_LIMIT disables limiting entirely.
    """
    settings = get_settings()
    default_limits = [settings.rate_limit] if settings.rate_limit else []
    return Limiter(
        key_func=get_remote_address,
        storage_uri=settings.rate_limit_storage_uri,
        default_limits=default_limits,
    )


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """FastAPI dependency enforcing API-key auth when keys are configured.

    No-op when auth is disabled. Uses a constant-time comparison against each configured
    key to avoid timing side channels.
    """
    settings = get_settings()
    if not settings.auth_enabled:
        return
    if x_api_key and any(
        secrets.compare_digest(x_api_key, key) for key in settings.api_key_set
    ):
        return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid API key.",
        headers={"WWW-Authenticate": "API-Key"},
    )
