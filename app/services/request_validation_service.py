"""Request validation service for handling request size and validation."""

from typing import Any

from fastapi import Request

from ..utils.request_size import format_bytes, validate_request_size


class RequestValidationService:
    """Service for request validation operations."""

    def __init__(self) -> None:
        """Initialize request validation service."""
        pass

    async def validate_request_size(self, request: Request, max_size: int = None) -> None:
        """Validate request size through service layer."""
        return await validate_request_size(request, max_size=max_size)

    def format_bytes(self, size: int) -> str:
        """Format bytes for display through service layer."""
        return format_bytes(size)
