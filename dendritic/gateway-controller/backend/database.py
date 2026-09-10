from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import text

from .config import get_settings
from .models import Base

engine: AsyncEngine = create_async_engine(
    get_settings().database_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)
Session = async_sessionmaker(engine, expire_on_commit=False)


async def session_scope() -> AsyncIterator[AsyncSession]:
    async with Session() as session:
        yield session


async def initialize_database() -> None:
    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT pg_advisory_lock(hashtext('syndichan-gateway-schema'))")
        )
        try:
            await connection.run_sync(Base.metadata.create_all)
            await connection.run_sync(_run_migrations)
        finally:
            await connection.execute(
                text("SELECT pg_advisory_unlock(hashtext('syndichan-gateway-schema'))")
            )


def _run_migrations(sync_connection) -> None:
    root = Path(__file__).resolve().parents[1]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    config.attributes["connection"] = sync_connection
    command.upgrade(config, "head")
