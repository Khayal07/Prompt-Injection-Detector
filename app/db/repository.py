"""Persistence of detection verdicts.

Logging must never break the request path: `log_detection` swallows and reports database
errors rather than propagating them, since a screening verdict is still valid even if it
could not be recorded.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.db.models import Detection
from app.schemas import CheckRequest, CheckResponse

logger = logging.getLogger("pid.repository")


def build_record(
    request: CheckRequest, response: CheckResponse, preview_chars: int
) -> Detection:
    """Construct a Detection ORM row from a request/response pair."""
    preview = request.text[:preview_chars] if preview_chars > 0 else ""
    return Detection(
        id=response.request_id,
        input_length=len(request.text),
        input_preview=preview,
        heuristic_score=response.heuristic_score,
        classifier_used=response.classifier.used,
        classifier_score=response.classifier.score,
        classifier_provider=response.classifier.provider,
        final_score=response.risk_score,
        label=response.label.value,
        action=response.action.value,
        matched_rule_ids=[r.id for r in response.matched_rules],
        latency_ms=response.latency_ms,
        classifier_latency_ms=response.classifier.latency_ms,
    )


def log_detection(
    session_factory: sessionmaker[Session],
    settings: Settings,
    request: CheckRequest,
    response: CheckResponse,
) -> bool:
    """Persist one detection. Returns True on success, False if logging failed.

    Never raises: a DB outage degrades logging, not the firewall itself.
    """
    if not settings.logging_enabled:
        return False
    try:
        record = build_record(request, response, settings.input_preview_chars)
        with session_factory() as session:
            session.add(record)
            session.commit()
        return True
    except Exception as exc:  # noqa: BLE001 - logging must not break the request
        logger.warning("failed to persist detection %s: %s", response.request_id, exc)
        return False
