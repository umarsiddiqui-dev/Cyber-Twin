"""
Tests for the health endpoint.
Uses httpx AsyncClient with ASGITransport — no real DB needed.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch


@pytest.fixture
def mock_db():
    """Mock the database dependency to avoid needing a real Postgres instance."""
    async def _get_db():
        yield AsyncMock()

    return _get_db


@pytest.mark.asyncio
async def test_health_endpoint(mock_db):
    from app.main import app
    from app.database import get_db

    app.dependency_overrides[get_db] = mock_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "timestamp" in data

    app.dependency_overrides.clear()
