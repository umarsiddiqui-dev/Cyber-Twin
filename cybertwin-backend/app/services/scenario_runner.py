"""
Scenario Runner Service – Phase 5 (Fixed Phase 2 Logic Bug)
Loads attack scenario definitions and replays log sequences through
the existing ingest_raw_log pipeline at realistic timing.

Phase 2 Fix:
  - is_running() previously always returned False because _running_task
    was only set by simulation.py (a different module), not by this module.
  - Solution: expose set_running_task() so simulation.py can register the
    asyncio.Task handle here after creating it. is_running() now correctly
    checks that registered task.

No external dependencies — runs entirely within the CyberTwin backend.
"""

import asyncio
import json
import logging
import random
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_DATA_PATH = Path(__file__).parent.parent / "data" / "attack_scenarios.json"

# ── Global running task registry ──────────────────────────────────────────────
# NOTE: This is set by simulation.py via set_running_task() after creating
# the task, NOT inside run_scenario() (which cannot capture asyncio.current_task
# reliably from within the coroutine itself).
_running_task: asyncio.Task | None = None
_running_scenario_id: str | None = None


def set_running_task(task: asyncio.Task | None) -> None:
    """
    Called by simulation.py AFTER asyncio.create_task() to register the
    running task handle with this module.
    Also called with None when the scenario is stopped/completed.
    """
    global _running_task
    _running_task = task


@dataclass
class ScenarioMeta:
    id: str
    name: str
    description: str
    mitre_tactics: list[str]
    severity: str
    duration_seconds: int
    log_count: int


def _load_scenarios() -> list[dict]:
    try:
        with open(_DATA_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"[ScenarioRunner] Failed to load scenarios: {e}")
        return []


_SCENARIOS: list[dict] = _load_scenarios()
_SCENARIO_MAP: dict[str, dict] = {s["id"]: s for s in _SCENARIOS}


def list_scenarios() -> list[ScenarioMeta]:
    """Return lightweight metadata for all available scenarios."""
    return [
        ScenarioMeta(
            id=s["id"],
            name=s["name"],
            description=s["description"],
            mitre_tactics=s.get("mitre_tactics", []),
            severity=s.get("severity", "HIGH"),
            duration_seconds=s.get("duration_seconds", 30),
            log_count=len(s.get("log_sequence", [])),
        )
        for s in _SCENARIOS
    ]


async def run_scenario(scenario_id: str, callback) -> int:
    """
    Replay a scenario's log sequence through the ingest pipeline.

    Args:
        scenario_id: The scenario 'id' field from attack_scenarios.json
        callback:    async callable(raw_log: str, source_hint: str)
                     — should be incident_service.ingest_raw_log

    Returns:
        Number of log lines ingested.
    """
    global _running_scenario_id

    scenario = _SCENARIO_MAP.get(scenario_id)
    if not scenario:
        raise ValueError(f"Unknown scenario: {scenario_id}")

    logs = scenario.get("log_sequence", [])
    duration = scenario.get("duration_seconds", 30)
    # Spread logs evenly across the duration with some jitter
    interval = duration / max(len(logs), 1)

    _running_scenario_id = scenario_id
    logger.info(f"[ScenarioRunner] Starting '{scenario['name']}' ({len(logs)} logs over ~{duration}s)")
    count = 0

    try:
        for log_line in logs:
            try:
                # Determine source hint from log content
                hint = "snort" if log_line.startswith("[**]") else "ossec"
                await callback(log_line, hint)
                count += 1
            except asyncio.CancelledError:
                logger.info(f"[ScenarioRunner] Scenario '{scenario_id}' cancelled after {count} logs")
                raise
            except Exception as e:
                logger.error(f"[ScenarioRunner] Log ingestion error: {e}")

            # Jitter ±20% for realism
            jitter = interval * random.uniform(0.8, 1.2)
            await asyncio.sleep(jitter)
    finally:
        # Always clear state when finished (normally or via cancellation)
        _running_scenario_id = None
        set_running_task(None)

    logger.info(f"[ScenarioRunner] '{scenario['name']}' complete ({count} logs emitted)")
    return count


def get_running_scenario() -> str | None:
    return _running_scenario_id


def is_running() -> bool:
    """
    Returns True only if the task registered via set_running_task() is still
    running. Correctly returns False when no task is registered or when the
    task has completed/been cancelled.
    """
    return _running_task is not None and not _running_task.done()
