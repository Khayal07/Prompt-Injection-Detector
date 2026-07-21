"""SQLAlchemy models for the detection log.

One row is written per /check call, capturing the verdict, the rules that fired, and
latency — the raw material for the evaluation and for operational monitoring.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Detection(Base):
    """A single screened request and its verdict."""

    __tablename__ = "detections"

    # Store the request id as a 32-char hex string so the schema is portable across
    # Postgres and SQLite (used in tests) without a native UUID type.
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )

    # Input metadata. The raw text is stored truncated (privacy) and may be empty when
    # INPUT_PREVIEW_CHARS is 0.
    input_length: Mapped[int] = mapped_column(Integer)
    input_preview: Mapped[str] = mapped_column(Text, default="")

    # Scores and verdict.
    heuristic_score: Mapped[float] = mapped_column(Float)
    classifier_used: Mapped[bool] = mapped_column(default=False)
    classifier_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    classifier_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    final_score: Mapped[float] = mapped_column(Float)
    label: Mapped[str] = mapped_column(String(16), index=True)
    action: Mapped[str] = mapped_column(String(16))

    # List of matched rule ids (JSON array; portable on both backends).
    matched_rule_ids: Mapped[list] = mapped_column(JSON, default=list)

    # Latency.
    latency_ms: Mapped[float] = mapped_column(Float)
    classifier_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debug convenience
        return (
            f"<Detection id={self.id} label={self.label} "
            f"score={self.final_score:.3f} action={self.action}>"
        )
