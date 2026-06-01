"""
CyberTwin Backend – Entry Point (Phase 7)
Starts log monitoring, ML model loading, knowledge base indexing,
and Ollama LLM warm-up ping.
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
from app.routers.ml_classify import router as ml_router        # Phase 6
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

    # ── Load ML model + knowledge base (Phase 6) ───────────────────────────
    from app.services import ml_service as _ml
    try:
        import asyncio as _asyncio
        await _asyncio.get_event_loop().run_in_executor(None, _ml.startup)
        logger.info("[Startup] ML model + knowledge base loaded")
    except Exception as e:
        logger.warning(f"[Startup] ML model not loaded (run model_trainer.py first): {e}")

    # ── Start conversation memory cleanup task (Phase 3) ──────────────────────
    from app.services import conversation_memory
    memory_task = conversation_memory.start_cleanup_task()
    logger.info("[Startup] Conversation memory cleanup task started")

    # ── Ollama warm-up ping (Phase 7) ─────────────────────────────────────────
    from app.services.ollama_client import health_check as ollama_health
    _ollama = await ollama_health()
    if _ollama["ollama_reachable"] and _ollama["model_loaded"]:
        logger.info(
            f"[Startup] ✅ Ollama reachable – model '{settings.OLLAMA_MODEL}' loaded and ready"
        )
    elif _ollama["ollama_reachable"]:
        logger.warning(
            f"[Startup] ⚠️  Ollama reachable but model '{settings.OLLAMA_MODEL}' not yet pulled. "
            f"Run: ollama pull {settings.OLLAMA_MODEL}"
        )
    else:
        logger.warning(
            "[Startup] ⚠️  Ollama not reachable at %s – chatbot will use offline fallback. "
            "Start Ollama with: ollama serve",
            settings.OLLAMA_BASE_URL,
        )

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
    version="7.0.0",
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
app.include_router(ml_router,          prefix="/api")   # Phase 6
app.include_router(ws_router)


@app.get("/", tags=["root"])
async def root():
    return {"service": "CyberTwin Backend", "version": "7.0.0", "status": "operational"}

