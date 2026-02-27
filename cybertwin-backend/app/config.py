"""
Application configuration – reads from .env or environment variables.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://cybertwin:cybertwin@localhost:5432/cybertwin_db"

    # App
    APP_NAME: str = "CyberTwin"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Security – Phase 1 JWT (now fully implemented)
    SECRET_KEY: str = "change-me-before-production-use"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Bootstrap analyst credentials (single-user Phase 1 auth)
    # REPLACEMENT POINT: swap for a DB users table in a future phase.
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "CyberTwin@Admin#2026"

    # ── Phase 2: Log monitoring ──────────────────────────────────────────────
    # Path to a real Snort/OSSEC alert log file (Track B – production).
    # If empty or not set, the simulator (Track A) will be used instead.
    LOG_FILE_PATH: str = ""

    # Simulator emission interval (seconds) – random between min and max
    LOG_SIMULATE_INTERVAL_MIN: float = 5.0
    LOG_SIMULATE_INTERVAL_MAX: float = 12.0

    # ── Phase 3 AI ────────────────────────────────────────────────────────────
    OPENAI_API_KEY: str = ""

    # ── Phase 4: Action execution safety gate ─────────────────────────────────
    # WARNING: Keep this False in development.
    # Set to true ONLY in a controlled lab environment.
    ALLOW_REAL_EXECUTION: bool = False

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
