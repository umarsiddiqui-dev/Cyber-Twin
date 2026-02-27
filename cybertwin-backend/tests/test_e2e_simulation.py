"""
Phase 5 – E2E Simulation Tests (Updated for yield_per streaming export)
Tests the scenario listing API, scenario runner service,
and CSV export endpoints.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch

from app.main import app
from app.services import scenario_runner


# ── Scenario listing ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scenario_list_returns_scenarios():
    """GET /api/simulation/scenarios returns at least 8 built-in scenarios."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/simulation/scenarios")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 8


@pytest.mark.asyncio
async def test_scenario_list_has_required_fields():
    """Each scenario in the list must have id, name, severity, and log_count."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/simulation/scenarios")
    for scenario in response.json():
        assert "id" in scenario
        assert "name" in scenario
        assert "severity" in scenario
        assert "log_count" in scenario
        assert scenario["log_count"] > 0


# ── Scenario runner service (unit) ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_unknown_scenario_raises():
    """Running an unknown scenario ID should raise ValueError."""
    async def _noop(log, hint=None):
        pass
    with pytest.raises(ValueError, match="Unknown scenario"):
        await scenario_runner.run_scenario("nonexistent_xyz", callback=_noop)


@pytest.mark.asyncio
async def test_scenario_runner_calls_callback():
    """The runner should call the ingest callback for each log line."""
    import asyncio

    collected = []

    async def fake_callback(log, hint=None):
        collected.append(log)

    # Use a short scenario — ssh_brute_force has 6 logs
    task = asyncio.create_task(
        scenario_runner.run_scenario("ssh_brute_force", fake_callback)
    )
    # Register the task so is_running() works correctly
    scenario_runner.set_running_task(task)
    # Wait just long enough for at least one log
    await asyncio.sleep(0.2)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    # At minimum the first callback should have fired
    assert len(collected) >= 1


# ── Export endpoints ──────────────────────────────────────────────────────────

def _make_streaming_mock():
    """
    Build a mock AsyncSession that works with the new db.stream() + yield_per path.
    The export router calls: db.stream(stmt) → result.scalars().partitions()
    partitions() is an async generator that yields lists of model instances.
    """
    session = MagicMock()

    # Create an async generator for scalars().partitions()
    async def _fake_partitions():
        # Yield an empty partition — represents an empty table
        yield []

    scalars_mock = MagicMock()
    scalars_mock.partitions = _fake_partitions  # async generator

    result_mock = MagicMock()
    result_mock.scalars.return_value = scalars_mock

    # db.stream() must be an async context manager that returns the result mock
    async def _fake_stream(stmt):
        return result_mock

    session.stream = _fake_stream

    async def _get_db():
        yield session

    return _get_db


@pytest.mark.asyncio
async def test_export_actions_csv_returns_200():
    """GET /api/export/actions.csv should return a CSV response (empty DB ok)."""
    from app.database import get_db

    app.dependency_overrides[get_db] = _make_streaming_mock()
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/export/actions.csv")
        assert response.status_code == 200
        assert "text/csv" in response.headers.get("content-type", "")
        assert "attachment" in response.headers.get("content-disposition", "")
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.mark.asyncio
async def test_export_incidents_csv_returns_200():
    """GET /api/export/incidents.csv should return a CSV response (empty DB ok)."""
    from app.database import get_db

    app.dependency_overrides[get_db] = _make_streaming_mock()
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/export/incidents.csv")
        assert response.status_code == 200
        assert "text/csv" in response.headers.get("content-type", "")
    finally:
        app.dependency_overrides.pop(get_db, None)
