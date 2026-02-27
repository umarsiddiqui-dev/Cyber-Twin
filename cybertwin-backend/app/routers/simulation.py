"""
Simulation Router – Phase 5 (Fixed Phase 2 Logic Bug)
Provides API endpoints to list, start, and stop attack scenario simulations.

Phase 2 Fix:
  - After asyncio.create_task(), calls scenario_runner.set_running_task(_task)
    so is_running() in scenario_runner works correctly.
  - On stop, calls scenario_runner.set_running_task(None) to clear state.
"""

import asyncio
import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services import scenario_runner
from app.services.incident_service import ingest_raw_log

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Simulation"])


class RunScenarioRequest(BaseModel):
    scenario_id: str


class ScenarioStatusResponse(BaseModel):
    running: bool
    scenario_id: str | None


# ── GET /api/simulation/scenarios ─────────────────────────────────────────────

@router.get("/simulation/scenarios", summary="List available attack scenarios")
async def list_scenarios():
    """Return metadata for all 8 built-in Atomic Red Team–inspired scenarios."""
    scenarios = scenario_runner.list_scenarios()
    return [
        {
            "id": s.id,
            "name": s.name,
            "description": s.description,
            "mitre_tactics": s.mitre_tactics,
            "severity": s.severity,
            "duration_seconds": s.duration_seconds,
            "log_count": s.log_count,
        }
        for s in scenarios
    ]


# ── POST /api/simulation/run ──────────────────────────────────────────────────

@router.post("/simulation/run", response_model=ScenarioStatusResponse, summary="Start an attack scenario")
async def run_scenario(body: RunScenarioRequest):
    """
    Launch a named scenario in the background.
    Logs are replayed through the real ingest pipeline — alerts appear live on the dashboard.
    """
    # Guard against concurrent scenarios — uses the now-correct is_running()
    if scenario_runner.is_running():
        raise HTTPException(
            status_code=409,
            detail=f"Scenario '{scenario_runner.get_running_scenario()}' is already running. Stop it first."
        )

    # Validate scenario exists
    known = {s.id for s in scenario_runner.list_scenarios()}
    if body.scenario_id not in known:
        raise HTTPException(status_code=404, detail=f"Unknown scenario: {body.scenario_id}")

    async def _run():
        try:
            await scenario_runner.run_scenario(body.scenario_id, ingest_raw_log)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"[SimRouter] Scenario error: {e}")
        finally:
            # Ensure state is cleared even if run_scenario raises unexpectedly
            scenario_runner.set_running_task(None)

    task = asyncio.create_task(_run())
    # ── Phase 2 Fix: register task with scenario_runner so is_running() works ──
    scenario_runner.set_running_task(task)

    logger.info(f"[SimRouter] Started scenario: {body.scenario_id}")
    return ScenarioStatusResponse(running=True, scenario_id=body.scenario_id)


# ── POST /api/simulation/stop ─────────────────────────────────────────────────

@router.post("/simulation/stop", response_model=ScenarioStatusResponse, summary="Stop the running scenario")
async def stop_scenario():
    """Cancel the currently running scenario (if any)."""
    running_task = scenario_runner._running_task  # access internal for cancellation

    if running_task and not running_task.done():
        running_task.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(running_task), timeout=2.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
        scenario_runner.set_running_task(None)
        logger.info("[SimRouter] Scenario stopped by user")
        return ScenarioStatusResponse(running=False, scenario_id=None)

    return ScenarioStatusResponse(running=False, scenario_id=None)


# ── GET /api/simulation/status ────────────────────────────────────────────────

@router.get("/simulation/status", response_model=ScenarioStatusResponse, summary="Get simulation status")
async def simulation_status():
    return ScenarioStatusResponse(
        running=scenario_runner.is_running(),
        scenario_id=scenario_runner.get_running_scenario(),
    )
