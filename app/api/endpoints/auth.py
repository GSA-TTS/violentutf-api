"""Authentication endpoints (placeholder for extraction)."""

from typing import Dict

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr
from structlog.stdlib import get_logger

from ...core.security import create_access_token, create_refresh_token, verify_password

logger = get_logger(__name__)
router = APIRouter()


class LoginRequest(BaseModel):
    """Login request model."""

    username: str
    password: str


class LoginResponse(BaseModel):
    """Login response model."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    """User creation request."""

    username: str
    email: EmailStr
    password: str


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest) -> LoginResponse:
    """Login endpoint (placeholder)."""
    # TODO: Implement actual user authentication
    # This is a placeholder that will be replaced in Phase 6

    # For now, just create tokens for testing
    if request.username == "test" and request.password == "test":  # pragma: allowlist secret
        access_token = create_access_token(data={"sub": request.username})
        refresh_token = create_refresh_token(data={"sub": request.username})

        logger.info("user_logged_in", username=request.username)

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate) -> Dict[str, str]:
    """Register new user (placeholder)."""
    # TODO: Implement actual user registration
    # This is a placeholder that will be replaced in Phase 6

    logger.info("user_registration_attempted", username=user.username)

    return {
        "message": "User registration will be implemented in Phase 6",
        "username": user.username,
    }
