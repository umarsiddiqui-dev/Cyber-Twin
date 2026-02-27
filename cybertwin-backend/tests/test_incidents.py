"""
Tests for GET /api/incidents (Phase 2).
Uses mocked DB to avoid requiring a running PostgreSQL instance.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock


@pytest.fixture
def mock_db_empty():
    """DB returns empty list for incidents queries."""
    async def _get_db():
        session = AsyncMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = []
        session.execute = AsyncMock(return_value=result)
        yield session
    return _get_db


@pytest.mark.asyncio
async def test_incidents_returns_list(mock_db_empty):
    from app.main import app
    from app.database import get_db

    app.dependency_overrides[get_db] = mock_db_empty

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/incidents")

    assert response.status_code == 200
    assert isinstance(response.json(), list)

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_incidents_limit_param(mock_db_empty):
    from app.main import app
    from app.database import get_db

    app.dependency_overrides[get_db] = mock_db_empty

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/incidents?limit=10")

    assert response.status_code == 200

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_incidents_invalid_limit(mock_db_empty):
    from app.main import app
    from app.database import get_db

    app.dependency_overrides[get_db] = mock_db_empty

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/incidents?limit=999")

    # 999 > max(200), should be rejected with 422
    assert response.status_code == 422

    app.dependency_overrides.clear()
