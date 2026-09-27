from unittest.mock import AsyncMock, MagicMock

import pytest

from backend import database


@pytest.mark.asyncio
async def test_schema_initialization_is_serialized(monkeypatch):
    connection = AsyncMock()
    transaction = AsyncMock()
    transaction.__aenter__.return_value = connection
    engine = MagicMock()
    engine.begin.return_value = transaction
    monkeypatch.setattr(database, "engine", engine)
    await database.initialize_database()
    statements = [str(call.args[0]) for call in connection.execute.call_args_list]
    assert "pg_advisory_lock" in statements[0]
    assert "pg_advisory_unlock" in statements[-1]
