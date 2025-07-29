"""Request size validation utilities."""

from typing import AsyncIterator, Optional

from fastapi import HTTPException, Request, status
from structlog.stdlib import get_logger

from ..core.config import settings

logger = get_logger(__name__)


async def validate_request_size(
    request: Request,
    max_size: Optional[int] = None,
) -> None:
    """Validate request size before processing.

    Args:
        request: FastAPI request object
        max_size: Maximum allowed size in bytes

    Raises:
        HTTPException: If request size exceeds limit
    """
    if max_size is None:
        max_size = settings.MAX_REQUEST_SIZE

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            size = int(content_length)
            if size > max_size:
                logger.warning(
                    "request_size_validation_failed",
                    size=size,
                    max_size=max_size,
                    path=request.url.path,
                )
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Request size {size} exceeds maximum {max_size} bytes",
                )
        except ValueError:
            logger.warning(
                "invalid_content_length",
                content_length=content_length,
                path=request.url.path,
            )


async def stream_with_size_limit(
    stream: AsyncIterator[bytes],
    max_size: int,
    chunk_size: int = 8192,
) -> AsyncIterator[bytes]:
    """Stream data with size limit enforcement.

    Args:
        stream: Async iterator of bytes
        max_size: Maximum allowed total size
        chunk_size: Size of chunks to yield

    Yields:
        Chunks of data

    Raises:
        HTTPException: If total size exceeds limit
    """
    total_size = 0

    async for chunk in stream:
        total_size += len(chunk)
        if total_size > max_size:
            logger.warning(
                "streaming_size_limit_exceeded",
                total_size=total_size,
                max_size=max_size,
            )
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Stream size exceeds maximum {max_size} bytes",
            )
        yield chunk


def get_size_limit_for_endpoint(path: str) -> int:
    """Get appropriate size limit for endpoint.

    Args:
        path: Request path

    Returns:
        Size limit in bytes
    """
    # Upload endpoints get higher limits
    upload_patterns = [
        "/upload",
        "/file",
        "/attachment",
        "/import",
        "/media",
        "/avatar",
        "/document",
    ]

    for pattern in upload_patterns:
        if pattern in path.lower():
            return settings.MAX_UPLOAD_SIZE

    return settings.MAX_REQUEST_SIZE


def format_bytes(size: float) -> str:
    """Format bytes as human-readable string.

    Args:
        size: Size in bytes

    Returns:
        Formatted string
    """
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size = size / 1024.0
    return f"{size:.2f} TB"
