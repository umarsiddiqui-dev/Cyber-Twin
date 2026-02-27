"""
Auth Dependencies – Phase 1 Security Hardening
Provides JWT creation and validation for FastAPI endpoints.

Security design:
  - Tokens are signed with HS256 using SECRET_KEY from config/env.
  - Expiry is controlled by ACCESS_TOKEN_EXPIRE_MINUTES in config.
  - get_current_user() is the FastAPI dependency injected into protected routes.
  - Returns the 'sub' claim string as the identity (analyst username).
"""

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from app.config import settings

# ── OAuth2 scheme (extracts Bearer token from Authorization header) ────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials. Please log in.",
    headers={"WWW-Authenticate": "Bearer"},
)


def create_access_token(subject: str, expires_delta: timedelta | None = None) -> str:
    """
    Create a signed JWT access token.

    Args:
        subject:       The user identity to embed in the 'sub' claim (e.g. username).
        expires_delta: Custom expiry duration. Defaults to ACCESS_TOKEN_EXPIRE_MINUTES.

    Returns:
        Encoded JWT string.
    """
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {"sub": subject, "exp": expire, "iat": datetime.now(timezone.utc)}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> str:
    """
    FastAPI dependency — validate the Bearer token and return the analyst identity.

    Raises HTTP 401 if the token is missing, expired, or invalid.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        subject: str | None = payload.get("sub")
        if not subject:
            raise _CREDENTIALS_EXCEPTION
        return subject
    except JWTError:
        raise _CREDENTIALS_EXCEPTION
