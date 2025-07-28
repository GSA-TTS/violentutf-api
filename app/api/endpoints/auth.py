"""Authentication endpoints with real database authentication."""

from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from ...core.errors import ValidationError
from ...core.security import create_access_token, create_refresh_token, validate_password_strength
from ...db.session import get_db
from ...repositories.user import UserRepository

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


class TokenRefreshRequest(BaseModel):
    """Token refresh request."""

    refresh_token: str


@router.post("/login", response_model=LoginResponse)
async def login(
    request: LoginRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> LoginResponse:
    """Authenticate user and return JWT tokens."""
    try:
        # Get client IP address for logging
        client_ip = http_request.client.host if http_request.client else None

        # Create user repository
        user_repo = UserRepository(db)

        # Authenticate user
        user = await user_repo.authenticate(
            username=request.username,
            password=request.password,
            ip_address=client_ip,
        )

        if not user:
            logger.warning(
                "authentication_failed",
                username=request.username,
                ip_address=client_ip,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check if user can login (active and verified)
        if not user.can_login():
            logger.warning(
                "login_denied_inactive_user",
                username=request.username,
                user_id=str(user.id),
                is_active=user.is_active,
                is_verified=user.is_verified,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is inactive or not verified",
            )

        # Create JWT tokens with complete claims per ADR-003
        token_data = {
            "sub": str(user.id),
            "roles": user.roles,
            "organization_id": str(user.organization_id) if user.organization_id else None,
        }
        access_token = create_access_token(data=token_data)
        refresh_token = create_refresh_token(data=token_data)

        logger.info(
            "user_logged_in_successfully",
            username=user.username,
            user_id=str(user.id),
            ip_address=client_ip,
        )

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
        )

    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(
            "login_error",
            username=request.username,
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service temporarily unavailable",
        )


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> Dict[str, str]:
    """Register a new user account."""
    try:
        # Validate password strength
        is_strong, message = validate_password_strength(user_data.password)
        if not is_strong:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password validation failed: {message}",
            )

        # Create user repository
        user_repo = UserRepository(db)

        # Check if username already exists
        existing_user = await user_repo.get_by_username(user_data.username)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists",
            )

        # Check if email already exists
        existing_email = await user_repo.get_by_email(user_data.email)
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already exists",
            )

        # Create user using repository method (password will be hashed internally)
        new_user = await user_repo.create_user(
            username=user_data.username,
            email=user_data.email,
            password=user_data.password,
            full_name=None,  # Can be added later
            is_superuser=False,
            created_by="registration",
        )

        logger.info(
            "user_registered_successfully",
            username=new_user.username,
            user_id=str(new_user.id),
            email=new_user.email,
        )

        return {
            "message": "User registered successfully",
            "username": new_user.username,
            "user_id": str(new_user.id),
            "note": "Email verification required before login",
        }

    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(
            "registration_error",
            username=user_data.username,
            email=user_data.email,
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration service temporarily unavailable",
        )


@router.post("/refresh", response_model=LoginResponse)
async def refresh_token(
    request: TokenRefreshRequest,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> LoginResponse:
    """Refresh access token using refresh token."""
    try:
        from ...core.security import decode_token

        # Decode and validate refresh token
        try:
            payload = decode_token(request.refresh_token)
        except ValueError as e:
            logger.warning("invalid_refresh_token", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Validate token type
        if payload.get("type") != "refresh":
            logger.warning("invalid_token_type_for_refresh", token_type=payload.get("type"))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type for refresh",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Get user ID from token
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Verify user still exists and is active
        user_repo = UserRepository(db)
        user = await user_repo.get(user_id)

        if not user or not user.can_login():
            logger.warning(
                "refresh_denied_invalid_user",
                user_id=user_id,
                user_exists=bool(user),
                can_login=user.can_login() if user else False,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is no longer valid",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Create new tokens (token rotation) with complete claims per ADR-003
        token_data = {
            "sub": str(user.id),
            "roles": user.roles,
            "organization_id": str(user.organization_id) if user.organization_id else None,
        }
        new_access_token = create_access_token(data=token_data)
        new_refresh_token = create_refresh_token(data=token_data)

        logger.info(
            "token_refreshed_successfully",
            user_id=str(user.id),
            username=user.username,
        )

        return LoginResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
        )

    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error("token_refresh_error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh service temporarily unavailable",
        )
