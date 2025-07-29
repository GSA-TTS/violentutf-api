"""Example endpoints demonstrating request signing."""

import time
from typing import Any, Dict, Optional

from appcore.config import settings
from appcore.decorators.request_signing import (
    require_admin_signature,
    require_request_signature,
    verify_webhook_signature,
)
from appcore.rate_limiting import rate_limit
from appcore.request_signing import (
    SignatureConfig,
    SignatureVersion,
    format_authorization_header,
    sign_request,
    signature_key_store,
)
from appdb.session import get_db
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

logger = get_logger(__name__)

router = APIRouter()


# Example models
class UserDeleteRequest(BaseModel):
    """Request to delete a user."""

    user_id: int = Field(..., description="User ID to delete")
    reason: str = Field(..., min_length=10, max_length=500)
    confirmed: bool = Field(..., description="Confirmation flag")


class BulkOperationRequest(BaseModel):
    """Request for bulk operations."""

    operation: str = Field(..., pattern="^(delete|update|export)$")
    entity_type: str = Field(..., pattern="^(users|products|orders)$")
    entity_ids: list[int] = Field(..., min_length=1, max_length=100)
    parameters: Optional[Dict[str, Any]] = None


class PaymentWebhookData(BaseModel):
    """Payment webhook data."""

    transaction_id: str
    amount: float
    currency: str
    status: str
    timestamp: int


class SignatureTestRequest(BaseModel):
    """Test request for signature validation."""

    message: str = Field(..., min_length=1, max_length=1000)
    timestamp: Optional[int] = Field(default_factory=lambda: int(time.time()))


# Initialize some test keys on module load
def initialize_test_keys() -> None:
    """Initialize test keys for demonstration."""
    # Add test keys
    signature_key_store.add_key(
        "test_key_1",
        "test_secret_1_very_long_and_secure_key_for_hmac",
        {"description": "Test key 1", "created_at": time.time()},
    )
    signature_key_store.add_key(
        "admin_key_1",
        "admin_secret_1_super_secure_key_for_admin_operations",
        {"description": "Admin key 1", "created_at": time.time(), "is_admin": True},
    )
    signature_key_store.add_key(
        "webhook_key_1",
        "webhook_secret_1_for_payment_provider",
        {"description": "Payment webhook key", "created_at": time.time()},
    )
    logger.info("test_keys_initialized", keys=signature_key_store.list_keys())


# Call it immediately when module is imported
initialize_test_keys()


@router.get("/signature/test")
@rate_limit("api")
async def test_signature_info() -> Dict[str, Any]:
    """Get information about request signing.

    This endpoint provides info about how to sign requests.
    """
    # Create example signature
    example_signature = sign_request(
        secret_key="example_secret",
        method="DELETE",
        path="/api/v1/example_request_signed/users/123",
        headers={"host": "api.example.com", "content-type": "application/json"},
        query_params={"confirm": "true"},
        body=b'{"reason": "Account deletion request"}',
        key_id="test_key_1",
    )

    return {
        "info": "Request signing protects sensitive operations",
        "available_keys": [
            {"key_id": key_id, "type": "admin" if key_id.startswith("admin_") else "standard"}
            for key_id in signature_key_store.list_keys()
        ],
        "example_request": {
            "method": "DELETE",
            "path": "/api/v1/example_request_signed/users/123",
            "headers": {
                "Authorization": format_authorization_header(example_signature),
                "Host": "api.example.com",
                "Content-Type": "application/json",
            },
            "body": '{"reason": "Account deletion request"}',
        },
        "signature_components": {
            "algorithm": example_signature.algorithm.value,
            "version": example_signature.version.value,
            "timestamp": example_signature.timestamp,
            "nonce": example_signature.nonce,
            "signature": example_signature.signature[:20] + "...",
        },
    }


@router.delete("/users/{user_id}")
@rate_limit("api")
@require_request_signature()
async def delete_user(
    user_id: int,
    request: Request,
    delete_request: UserDeleteRequest,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Delete a user - requires signed request.

    This endpoint demonstrates basic request signing requirement.
    The signature must be provided in the Authorization header.

    Example signed request:
    ```
    DELETE /api/v1/example_request_signed/users/123
    Authorization: Signature keyId="test_key_1",algorithm="HMAC-SHA256",headers="host content-type",timestamp="1234567890",nonce="abc123",signature="..."
    Host: api.example.com
    Content-Type: application/json

    {"user_id": 123, "reason": "User requested account deletion", "confirmed": true}
    ```
    """
    # Verify user_id matches
    if user_id != delete_request.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User ID mismatch",
        )

    # Check confirmation
    if not delete_request.confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Deletion not confirmed",
        )

    # Get signature info from request state
    signature_info = getattr(request.state, "signature", None)
    key_id = getattr(request.state, "signature_key_id", None)

    logger.info(
        "user_deletion_requested",
        user_id=user_id,
        reason=delete_request.reason,
        signed_by=key_id,
    )

    # In real implementation, would delete from database
    # For demo, just return success
    return {
        "deleted": True,
        "user_id": user_id,
        "reason": delete_request.reason,
        "deleted_at": time.time(),
        "deleted_by_key": key_id,
        "signature_algorithm": signature_info.algorithm.value if signature_info else None,
    }


@router.post("/admin/bulk-operation")
@rate_limit("api")
@require_admin_signature()
async def admin_bulk_operation(
    request: Request,
    operation: BulkOperationRequest,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Perform bulk admin operation - requires admin signature.

    This endpoint demonstrates admin-level signature requirement.
    Only requests signed with admin keys (key_id starting with 'admin_') are allowed.

    Example:
    ```
    POST /api/v1/example_request_signed/admin/bulk-operation
    Authorization: Signature keyId="admin_key_1",algorithm="HMAC-SHA256",...
    ```
    """
    # Get signature info
    key_id = getattr(request.state, "signature_key_id", None)
    is_admin = getattr(request.state, "is_admin_request", False)

    if not is_admin:
        # This should not happen if decorator works correctly
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    logger.info(
        "admin_bulk_operation",
        operation=operation.operation,
        entity_type=operation.entity_type,
        count=len(operation.entity_ids),
        admin_key=key_id,
    )

    # Simulate operation
    results = []
    for entity_id in operation.entity_ids[:5]:  # Process first 5 for demo
        results.append(
            {
                "entity_id": entity_id,
                "operation": operation.operation,
                "status": "success",
                "timestamp": time.time(),
            }
        )

    return {
        "operation": operation.operation,
        "entity_type": operation.entity_type,
        "total_entities": len(operation.entity_ids),
        "processed": len(results),
        "results": results,
        "performed_by": key_id,
        "is_admin_operation": True,
    }


@router.post("/webhooks/payment")
@rate_limit("webhook")
@verify_webhook_signature(
    secret_key="webhook_secret_1_for_payment_provider",
    signature_header="X-Payment-Signature",
    timestamp_header="X-Payment-Timestamp",
)
async def payment_webhook(
    request: Request,
    webhook_data: PaymentWebhookData,
) -> Dict[str, Any]:
    """Receive payment webhook - requires webhook signature.

    This endpoint demonstrates webhook signature verification.
    The webhook provider must sign the request with the shared secret.

    Expected headers:
    - X-Payment-Signature: HMAC signature of timestamp + body
    - X-Payment-Timestamp: Unix timestamp

    Example:
    ```
    POST /api/v1/example_request_signed/webhooks/payment
    X-Payment-Signature: abc123def456...
    X-Payment-Timestamp: 1234567890
    Content-Type: application/json

    {"transaction_id": "tx_123", "amount": 99.99, ...}
    ```
    """
    logger.info(
        "payment_webhook_received",
        transaction_id=webhook_data.transaction_id,
        amount=webhook_data.amount,
        status=webhook_data.status,
    )

    # Process webhook (in real app, would update payment status)
    return {
        "received": True,
        "transaction_id": webhook_data.transaction_id,
        "processed_at": time.time(),
        "webhook_valid": True,
    }


@router.post("/signature/generate")
@rate_limit("api")
async def generate_signature_example(
    request_data: SignatureTestRequest,
) -> Dict[str, Any]:
    """Generate an example signature for testing.

    This endpoint helps developers understand how to sign their requests.
    It generates a valid signature for a hypothetical request.
    """
    # Example request details
    method = "POST"
    path = "/api/v1/example_request_signed/test-signed-endpoint"
    headers = {
        "host": "api.example.com",
        "content-type": "application/json",
        "content-length": str(len(request_data.message)),
    }
    body = request_data.model_dump_json().encode()

    # Generate signature with test key
    test_key = signature_key_store.get_key("test_key_1")
    if not test_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Test key not found",
        )

    signature = sign_request(
        secret_key=test_key,
        method=method,
        path=path,
        headers=headers,
        body=body,
        key_id="test_key_1",
    )

    # Create curl command example
    curl_command = f"""curl -X {method} \\
  '{path}' \\
  -H 'Authorization: {format_authorization_header(signature)}' \\
  -H 'Host: {headers['host']}' \\
  -H 'Content-Type: {headers['content-type']}' \\
  -d '{request_data.model_dump_json()}'"""

    return {
        "request": {
            "method": method,
            "path": path,
            "headers": headers,
            "body": request_data.model_dump(),
        },
        "signature": {
            "authorization_header": format_authorization_header(signature),
            "components": {
                "key_id": signature.key_id,
                "algorithm": signature.algorithm.value,
                "timestamp": signature.timestamp,
                "nonce": signature.nonce,
                "signature": signature.signature,
            },
        },
        "curl_example": curl_command,
        "notes": [
            "The signature is valid for 5 minutes from the timestamp",
            "The nonce prevents replay attacks",
            "The signature covers method, path, headers, and body",
        ],
    }


@router.post("/test-signed-endpoint")
@rate_limit("api")
@require_request_signature(
    allowed_key_ids=["test_key_1", "test_key_2"],
    custom_error_message="This endpoint requires a signature from an authorized test key",
)
async def test_signed_endpoint(
    request: Request,
    test_data: SignatureTestRequest,
) -> Dict[str, Any]:
    """Test endpoint that requires specific key signatures.

    This endpoint demonstrates:
    1. Restricting signatures to specific key IDs
    2. Custom error messages
    3. Accessing signature information in the endpoint
    """
    # Get signature details
    signature = getattr(request.state, "signature", None)
    key_id = getattr(request.state, "signature_key_id", None)

    return {
        "success": True,
        "message": f"Request successfully signed and verified with key: {key_id}",
        "request_data": test_data.model_dump(),
        "signature_details": {
            "key_id": key_id,
            "algorithm": signature.algorithm.value if signature else None,
            "timestamp": signature.timestamp if signature else None,
            "age_seconds": int(time.time()) - signature.timestamp if signature else None,
        },
    }


@router.get("/signature/verify-status")
@rate_limit("api")
async def verify_signature_status(request: Request) -> Dict[str, Any]:
    """Check if the current request has a valid signature.

    This endpoint can be called with or without a signature.
    It reports the signature status of the request.
    """
    # Check for authorization header
    auth_header = request.headers.get("authorization", "")
    has_signature = auth_header.startswith("Signature ")

    # Check request state (would be set by middleware or decorator)
    signature_verified = getattr(request.state, "signature", None) is not None
    key_id = getattr(request.state, "signature_key_id", None)

    return {
        "has_authorization_header": bool(auth_header),
        "has_signature_format": has_signature,
        "signature_verified": signature_verified,
        "key_id": key_id,
        "recommendation": (
            "Request is properly signed" if signature_verified else "Add signature for sensitive operations"
        ),
    }
