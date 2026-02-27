"""
CyberTwin Backend – Entry Point (Phase 5)
Starts the log monitoring background task and conversation memory cleanup.
"""

import asyncio
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.database import create_tables
from app.config import settings
from app.routers import health, chat, incidents
from app.routers.actions import router as actions_router
from app.routers.simulation import router as simulation_router  # Phase 5
from app.routers.export import router as export_router          # Phase 5
from app.auth.router import router as auth_router               # Phase 1 security
from app.ws.log_stream import router as ws_router
from app.services.incident_service import ingest_raw_log

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup:
      1. Create DB tables.
      2. Start log monitor task (simulator OR file tailer based on config).
    Shutdown:
      Cancel the monitor task cleanly.
    """
    await create_tables()

    # ── Start conversation memory cleanup task (Phase 3) ──────────────────────
    from app.services import conversation_memory
    memory_task = conversation_memory.start_cleanup_task()
    logger.info("[Startup] Conversation memory cleanup task started")

    # ── Choose monitoring track ───────────────────────────────────────────────
    if settings.LOG_FILE_PATH:
        from app.services.log_tailer import tail_log_file
        logger.info(f"[Startup] Track B: Tailing log file → {settings.LOG_FILE_PATH}")
        monitor_task = asyncio.create_task(
            tail_log_file(settings.LOG_FILE_PATH, ingest_raw_log)
        )
    else:
        from app.services.log_simulator import run_simulator
        logger.warning(
            "⚠️  [Startup] RUNNING IN SIMULATION MODE – no real log file configured. "
            "Set LOG_FILE_PATH in .env to ingest live Snort/OSSEC alerts."
        )
        monitor_task = asyncio.create_task(
            run_simulator(
                ingest_raw_log,
                interval_min=settings.LOG_SIMULATE_INTERVAL_MIN,
                interval_max=settings.LOG_SIMULATE_INTERVAL_MAX,
            )
        )

    yield  # ← application is running

    # ── Shutdown ──────────────────────────────────────────────────────────────
    logger.info("[Shutdown] Stopping all background tasks…")
    conversation_memory.stop_cleanup_task()
    monitor_task.cancel()
    try:
        await monitor_task
    except asyncio.CancelledError:
        pass
    logger.info("[Shutdown] All tasks stopped cleanly")


app = FastAPI(
    title="CyberTwin API",
    description="AI-Powered SOC Assistant – Backend API",
    version="5.0.0",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router,        prefix="/api")   # Phase 1 security
app.include_router(health.router,      prefix="/api")
app.include_router(chat.router,        prefix="/api")
app.include_router(incidents.router,   prefix="/api")
app.include_router(actions_router,     prefix="/api")   # Phase 4
app.include_router(simulation_router,  prefix="/api")   # Phase 5
app.include_router(export_router,      prefix="/api")   # Phase 5
app.include_router(ws_router)


@app.get("/", tags=["root"])
async def root():
    return {"service": "CyberTwin Backend", "version": "5.0.0", "status": "operational"}

