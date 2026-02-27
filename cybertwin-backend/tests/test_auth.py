"""
Phase 1 Security Tests – JWT Authentication
Tests for the auth router (login) and the secured action endpoints.
Verifies that:
  - Valid credentials return a JWT.
  - Wrong credentials return 401.
  - Approve/Reject endpoints return 401 without a token.
  - Approve/Reject endpoints succeed with a valid token.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch

# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_token(client: AsyncClient) -> str:
    """
    Obtain a Bearer token using the test admin credentials.
    Uses the defaults from config.py (ADMIN_USERNAME='admin').
    """
    response = await client.post(
        "/api/auth/login",
        content="username=admin&password=CyberTwin%40Admin%232026",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200, f"Login failed: {response.text}"
    return response.json()["access_token"]


# ── Login endpoint tests ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_returns_token():
    """Valid credentials should return an access_token."""
    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        token = await _get_token(client)
    assert len(token) > 20


@pytest.mark.asyncio
async def test_login_wrong_password_returns_401():
    """Invalid credentials must return HTTP 401."""
    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/auth/login",
            content="username=admin&password=wrongpassword",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_user_returns_401():
    """Completely unknown username must return HTTP 401."""
    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/auth/login",
            content="username=hacker&password=h4ck3d",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    assert response.status_code == 401


# ── Protected endpoint tests ──────────────────────────────────────────────────

@pytest.fixture
def mock_db_for_auth():
    """Minimal DB mock for action endpoint tests."""
    async def _get_db():
        session = AsyncMock()
        # Return None for scalar_one_or_none (action not found) by default
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=result)
        yield session
    return _get_db


@pytest.mark.asyncio
async def test_approve_without_token_returns_401(mock_db_for_auth):
    """Calling /approve without a Bearer token must be rejected with 401."""
    from app.main import app
    from app.database import get_db
    app.dependency_overrides[get_db] = mock_db_for_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/actions/some-fake-id/approve", json={})
    assert response.status_code == 401
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_reject_without_token_returns_401(mock_db_for_auth):
    """Calling /reject without a Bearer token must be rejected with 401."""
    from app.main import app
    from app.database import get_db
    app.dependency_overrides[get_db] = mock_db_for_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/actions/some-fake-id/reject",
            json={"reason": "test"},
        )
    assert response.status_code == 401
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_approve_with_invalid_token_returns_401(mock_db_for_auth):
    """A malformed or expired JWT must be rejected with 401."""
    from app.main import app
    from app.database import get_db
    app.dependency_overrides[get_db] = mock_db_for_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/actions/some-fake-id/approve",
            json={},
            headers={"Authorization": "Bearer this.is.garbage"},
        )
    assert response.status_code == 401
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_approve_with_valid_token_proceeds_to_404(mock_db_for_auth):
    """
    A valid JWT should pass the auth gate.
    Since the mock DB returns no action, expect 404 (not 401),
    proving the auth dependency was satisfied.
    """
    from app.main import app
    from app.database import get_db
    app.dependency_overrides[get_db] = mock_db_for_auth
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        token = await _get_token(client)
        response = await client.post(
            "/api/actions/non-existent-id/approve",
            json={},
            headers={"Authorization": f"Bearer {token}"},
        )
    # 404 proves auth passed (JWT was valid); action not found because DB is mocked
    assert response.status_code == 404
    app.dependency_overrides.clear()
