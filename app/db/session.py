"""Database engine and session management.

Driven entirely by `DATABASE_URL`, so the same code runs against Postgres (production /
docker-compose) and SQLite (tests) without changes.
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.models import Base


def make_engine(database_url: str) -> Engine:
    """Create a SQLAlchemy engine for the given URL.

    SQLite needs `check_same_thread=False` so a connection can be shared across the
    threadpool FastAPI uses for sync endpoints.
    """
    connect_args = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    return create_engine(database_url, pool_pre_ping=True, connect_args=connect_args)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a session factory bound to `engine`."""
    return sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


def init_db(engine: Engine) -> None:
    """Create all tables if they do not yet exist."""
    Base.metadata.create_all(engine)
