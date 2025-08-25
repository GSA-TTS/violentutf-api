"""Example authentication endpoints with comprehensive input validation.

This demonstrates how to integrate the input validation framework with API endpoints.
"""

from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.api.deps import get_audit_service
from app.db.session import get_db
from app.services.audit_service import AuditService

from ...core.errors import ValidationError
from ...core.input_validation import (
    EMAIL_RULE,
    PASSWORD_RULE,
    USERNAME_RULE,
    FieldValidationRule,
    ValidationConfig,
    ValidationLevel,
    validate_input,
    validate_request_data,
)
from ...core.rate_limiting import rate_limit
from ...core.security import create_access_token, create_refresh_token, validate_password_strength
from ...db.session import get_db_dependency
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


# Define validation rules for login endpoint
LOGIN_VALIDATION_RULES = [
    FieldValidationRule(
        field_name="username",
        field_type=str,
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_@.-]+$",  # Allow email as username
        check_sql_injection=True,
        error_message="Username must be 3-50 characters",
    ),
    FieldValidationRule(
        field_name="password",
        field_type=str,
        min_length=1,  # Don't enforce password rules on login
        max_length=128,
        check_sql_injection=False,  # Passwords may contain special chars
        check_xss=False,
    ),
]

# Define validation rules for registration
REGISTER_VALIDATION_RULES = [
    USERNAME_RULE,
    EMAIL_RULE,
    PASSWORD_RULE,
]

# Define validation rules for token refresh
TOKEN_REFRESH_RULES = [
    FieldValidationRule(
        field_name="refresh_token",
        field_type=str,
        min_length=10,
        max_length=1000,
        pattern=r"^[A-Za-z0-9_.-]+$",  # JWT token pattern
        check_sql_injection=False,
        check_xss=False,
        error_message="Invalid token format",
    ),
]

# Strict validation for auth endpoints
AUTH_VALIDATION_CONFIG = ValidationConfig(
    level=ValidationLevel.STRICT,
    reject_additional_fields=True,
    log_validation_failures=True,
)


@router.post("/login", response_model=LoginResponse)
@validate_input(
    rules=LOGIN_VALIDATION_RULES,
    config=AUTH_VALIDATION_CONFIG,
    validate_json=True,
)
async def login(
    request: LoginRequest,
    http_request: Request,
    audit_service: AuditService = Depends(get_audit_service),
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    """Authenticate user and return JWT tokens with comprehensive input validation."""
    try:
        # Input has already been validated by decorator
        # Additional manual validation can be done here if needed

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
@validate_input(
    rules=REGISTER_VALIDATION_RULES,
    config=AUTH_VALIDATION_CONFIG,
    validate_json=True,
)
async def register(
    user_data: UserCreate,
    audit_service: AuditService = Depends(get_audit_service),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, str]:
    """Register a new user account with comprehensive input validation."""
    try:
        # Input has already been validated by decorator
        # Additional password strength validation
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
@validate_input(
    rules=TOKEN_REFRESH_RULES,
    config=AUTH_VALIDATION_CONFIG,
    validate_json=True,
    validate_query=True,
    allowed_query_params=set(),  # No query params allowed
)
async def refresh_token(
    request: TokenRefreshRequest,
    audit_service: AuditService = Depends(get_audit_service),
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    """Refresh access token using refresh token with comprehensive validation."""
    try:
        from ...core.security import decode_token

        # Input has already been validated by decorator
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
