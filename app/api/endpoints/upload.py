"""File upload endpoints with size validation example."""

from typing import Any, Dict

from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status
from structlog.stdlib import get_logger

from ...core.config import settings
from ...utils.request_size import format_bytes, validate_request_size

logger = get_logger(__name__)
router = APIRouter()


@router.post("/upload/file")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
) -> Dict[str, str]:
    """Upload a file with size validation.

    Args:
        request: FastAPI request
        file: Uploaded file

    Returns:
        Upload result with file info

    Raises:
        HTTPException: If file is too large or invalid
    """
    # The RequestSizeLimitMiddleware will handle size validation automatically
    # This is just an example of manual validation if needed

    # Validate file size from content-length if available
    await validate_request_size(request, max_size=settings.MAX_UPLOAD_SIZE)

    # Additional file-specific validation
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No filename provided",
        )

    # Check file extension
    allowed_extensions = {".txt", ".pdf", ".doc", ".docx", ".csv", ".json"}
    file_ext = "." + file.filename.split(".")[-1].lower() if "." in file.filename else ""

    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type {file_ext} not allowed. Allowed types: {', '.join(allowed_extensions)}",
        )

    # Read file with size tracking (middleware already enforces limits)
    content = await file.read()
    file_size = len(content)

    logger.info(
        "file_uploaded",
        filename=file.filename,
        size=file_size,
        content_type=file.content_type,
        formatted_size=format_bytes(file_size),
    )

    return {
        "filename": file.filename,
        "size": str(file_size),
        "size_formatted": format_bytes(file_size),
        "content_type": file.content_type or "application/octet-stream",
        "message": "File uploaded successfully",
    }


@router.post("/upload/multiple")
async def upload_multiple_files(
    request: Request,
    files: list[UploadFile] = File(...),
) -> Dict[str, Any]:
    """Upload multiple files with total size validation.

    Args:
        request: FastAPI request
        files: List of uploaded files

    Returns:
        Upload result with files info

    Raises:
        HTTPException: If total size exceeds limit
    """
    if not files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No files provided",
        )

    if len(files) > 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 10 files allowed per upload",
        )

    total_size = 0
    uploaded_files = []

    for file in files:
        if not file.filename:
            continue

        content = await file.read()
        file_size = len(content)
        total_size += file_size

        # Check if total size exceeds limit
        if total_size > settings.MAX_UPLOAD_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Total size {format_bytes(total_size)} exceeds maximum {format_bytes(settings.MAX_UPLOAD_SIZE)}",
            )

        uploaded_files.append(
            {
                "filename": file.filename,
                "size": file_size,
                "size_formatted": format_bytes(file_size),
            }
        )

    logger.info(
        "multiple_files_uploaded",
        count=len(uploaded_files),
        total_size=total_size,
        total_size_formatted=format_bytes(total_size),
    )

    return {
        "files": uploaded_files,
        "total_files": len(uploaded_files),
        "total_size": total_size,
        "total_size_formatted": format_bytes(total_size),
        "message": f"Successfully uploaded {len(uploaded_files)} files",
    }
