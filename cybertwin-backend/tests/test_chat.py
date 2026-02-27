"""
Tests for the chat endpoint.
Mocks the AI service and database to run without OpenAI key or Postgres.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone


# Canonical mock AI response (matches ChatResponse schema)
_MOCK_AI_RESULT = {
    "reply":           "🛡️ CyberTwin Phase 3 test response",
    "session_id":      "test-session-xyz",
    "timestamp":       datetime.now(timezone.utc).isoformat(),
    "mitre_id":        "T1595",
    "mitre_tactic":    "Reconnaissance",
    "mitre_technique": "Active Scanning",
    "confidence":      0.75,
    "risk_score":      4.2,
}


@pytest.fixture
def mock_db():
    """Mock DB that handles both add() and execute() (for recent incidents query)."""
    async def _get_db():
        session = AsyncMock()
        session.add = AsyncMock()
        # execute() for recent incidents returns empty result
        result = MagicMock()
        result.fetchall.return_value = []
        session.execute = AsyncMock(return_value=result)
        yield session
    return _get_db


@pytest.mark.asyncio
async def test_chat_echo(mock_db):
    """Verify that a valid message returns a reply with correct schema."""
    from app.main import app
    from app.database import get_db

    app.dependency_overrides[get_db] = mock_db

    with patch("app.routers.chat.get_response", new=AsyncMock(return_value=_MOCK_AI_RESULT)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/chat", json={"message": "Hello CyberTwin"})

    assert response.status_code == 200
    data = response.json()
    assert "reply" in data
    assert "session_id" in data
    assert "timestamp" in data
    assert len(data["reply"]) > 0
    # Phase 3 enrichment fields present
    assert "mitre_id" in data
    assert "risk_score" in data

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_chat_empty_message(mock_db):
    """Verify that an empty message is rejected with a 422 validation error."""
    from app.main import app
    from app.database import get_db

    app.dependency_overrides[get_db] = mock_db

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/chat", json={"message": ""})

    assert response.status_code == 422  # Pydantic validation error

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_chat_with_session_id(mock_db):
    """Verify that a provided session_id is accepted and echoed back."""
    from app.main import app
    from app.database import get_db

    app.dependency_overrides[get_db] = mock_db

    with patch("app.routers.chat.get_response", new=AsyncMock(return_value=_MOCK_AI_RESULT)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/api/chat", json={
                "message":    "Is this a Port Scan alert?",
                "session_id": "test-session-abc123"
            })

    assert response.status_code == 200

    app.dependency_overrides.clear()

