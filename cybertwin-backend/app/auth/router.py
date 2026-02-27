"""
Auth Router – Phase 1 Security Hardening
Provides a login endpoint that validates credentials and returns a JWT.

Single-analyst bootstrap model:
  ADMIN_USERNAME and ADMIN_PASSWORD are read from .env via settings.

Password comparison:
  Uses passlib with a scheme priority list: bcrypt → sha256_crypt → md5_crypt.
  This gracefully handles environments where the bcrypt C backend is not compiled
  (common in Windows venvs without build tools). The comparison is done lazily
  inside the request handler — no hashing at module import time to avoid startup
  errors in environments with missing backends.

REPLACEMENT POINT (Future Phase):
  Replace in-memory credential check with a DB users table + Alembic migration.
"""

import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext

from app.config import settings
from app.auth.dependencies import create_access_token

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Auth"])

# ── Password hashing context ──────────────────────────────────────────────────
# Scheme list: use pbkdf2_sha256 (Python standard library compatible, no C
# extensions required). This avoids known bugs between passlib and bcrypt>=4.0.
_pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
)

_ADMIN_USERNAME: str = settings.ADMIN_USERNAME
_ADMIN_PASSWORD: str = settings.ADMIN_PASSWORD

# Pre-compute hash lazily (done on first login request, not at import time)
_admin_password_hash: str | None = None


def _get_admin_hash() -> str:
    """Return the cached bcrypt hash of the admin password, computing it on first call."""
    global _admin_password_hash
    if _admin_password_hash is None:
        _admin_password_hash = _pwd_context.hash(_ADMIN_PASSWORD)
    return _admin_password_hash


def _verify_password(plain: str, hashed: str) -> bool:
    return _pwd_context.verify(plain, hashed)


# ── POST /api/auth/login ──────────────────────────────────────────────────────

@router.post(
    "/auth/login",
    summary="Obtain a Bearer JWT token",
    response_model=dict,
)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Accepts username + password (form-encoded, OAuth2 standard).
    Returns a Bearer JWT on success, HTTP 401 on failure.

    Example curl:
        curl -X POST /api/auth/login \\
             -d "username=admin&password=yourpassword" \\
             -H "Content-Type: application/x-www-form-urlencoded"
    """
    # Use constant-time username comparison to prevent username enumeration
    username_ok = secrets.compare_digest(
        form_data.username.encode(), _ADMIN_USERNAME.encode()
    )
    password_ok = _verify_password(form_data.password, _get_admin_hash())

    if not (username_ok and password_ok):
        logger.warning(f"[Auth] Failed login attempt for username: {form_data.username!r}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(subject=form_data.username)
    logger.info(f"[Auth] Token issued for: {form_data.username!r}")

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "username": form_data.username,
    }
