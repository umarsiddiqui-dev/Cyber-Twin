"""
Health Router – Phase 7
Extended to report Ollama LLM connectivity, model availability,
and context indexer stats alongside the standard service status.
"""

from fastapi import APIRouter
from datetime import datetime, timezone
from app.config import settings

router = APIRouter(tags=["Health"])


@router.get("/health", summary="Backend health check")
async def health_check():
    """
    Returns service status, version, and Phase 7 Ollama/context diagnostics.
    Used by the frontend Topbar and ops monitoring.
    """
    from app.services.ollama_client import health_check as ollama_health
    from app.services.context_indexer import get_project_summary

    ollama_status  = await ollama_health()
    context_stats  = get_project_summary()

    return {
        "status":    "ok",
        "service":   settings.APP_NAME,
        "version":   settings.APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "llm": {
            "provider":      "ollama",
            "model":         settings.OLLAMA_MODEL,
            "base_url":      settings.OLLAMA_BASE_URL,
            **ollama_status,
        },
        "context_indexer": context_stats,
    }

