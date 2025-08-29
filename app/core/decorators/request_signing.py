"""Decorators for request signing enforcement."""

import functools
import inspect
import time
from typing import Any, Callable, List, Optional

from fastapi import HTTPException, Request, status
from structlog.stdlib import get_logger

from ..request_signing import (
    SignatureConfig,
    nonce_cache,
    parse_authorization_header,
    signature_key_store,
    verify_signature,
)

logger = get_logger(__name__)


def require_request_signature(
    config: Optional[SignatureConfig] = None,
    allowed_key_ids: Optional[List[str]] = None,
    custom_error_message: Optional[str] = None,
) -> Callable[..., Any]:
    """Decorator to require request signature for an endpoint.

    Args:
        config: Signature configuration
        allowed_key_ids: List of allowed key IDs (None allows all)
        custom_error_message: Custom error message

    Returns:
        Decorator function

    Example:
        ```python
        @router.delete("/users/{user_id}")
        @require_request_signature()
        async def delete_user(user_id: int, request: Request):
            # Only accessible with valid signature
            return {"deleted": user_id}
        ```
    """
    if config is None:
        config = SignatureConfig()

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Find Request object in arguments
            request = None
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            for param_name, param_value in bound_args.arguments.items():
                if isinstance(param_value, Request):
                    request = param_value
                    break

            if not request:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found in endpoint parameters",
                )

            # Check if signature was already verified by middleware
            if hasattr(request.state, "signature") and request.state.signature:
                # Already verified by middleware
                logger.debug("signature_already_verified", endpoint=func.__name__)
                return await func(*args, **kwargs)

            # Get Authorization header
            auth_header = request.headers.get("authorization", "")
            if not auth_header:
                error_msg = custom_error_message or "Request signature required"
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=error_msg,
                )

            # Parse signature
            signature = parse_authorization_header(auth_header)
            if not signature:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid Authorization header format",
                )

            # Check allowed key IDs
            if allowed_key_ids and signature.key_id not in allowed_key_ids:
                logger.warning(
                    "unauthorized_key_id",
                    key_id=signature.key_id,
                    allowed_key_ids=allowed_key_ids,
                    endpoint=func.__name__,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Key ID not authorized for this operation",
                )

            # Get signing key
            if not signature.key_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Missing key ID in signature",
                )

            secret_key = signature_key_store.get_key(signature.key_id)
            if not secret_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Unknown key ID",
                )

            # Read body if needed
            body = None
            if config.include_body and request.method in ["POST", "PUT", "PATCH"]:
                # Check if body was already read
                if hasattr(request, "_body"):
                    body = request._body
                else:
                    body = await request.body()
                    request._body = body

            # Extract headers and query params
            headers = dict(request.headers)
            query_params = dict(request.query_params) if request.query_params else None

            # Verify signature
            result = verify_signature(
                secret_key=secret_key,
                method=request.method,
                path=request.url.path,
                headers=headers,
                provided_signature=signature,
                query_params=query_params,
                body=body,
                config=config,
                nonce_cache=set(nonce_cache._nonces.keys()) if hasattr(nonce_cache, "_nonces") else None,
            )

            if not result.is_valid:
                logger.warning(
                    "signature_verification_failed",
                    endpoint=func.__name__,
                    key_id=signature.key_id,
                    error=result.error,
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Signature verification failed: {result.error}",
                )

            # Store signature info in request state
            request.state.signature = signature
            request.state.signature_key_id = signature.key_id

            logger.info(
                "signature_verified_by_decorator",
                endpoint=func.__name__,
                key_id=signature.key_id,
                signature_age=result.signature_age,
            )

            return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            # For sync endpoints, we can't do async operations
            # So we require the middleware to handle signing
            raise NotImplementedError(
                "Request signature decorator only supports async endpoints. "
                "Use RequestSigningMiddleware for sync endpoints."
            )

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def require_admin_signature(
    admin_key_prefix: str = "admin_",
    custom_error_message: Optional[str] = None,
) -> Callable[..., Any]:
    """Decorator to require admin-level request signature.

    Args:
        admin_key_prefix: Prefix for admin keys
        custom_error_message: Custom error message

    Returns:
        Decorator function

    Example:
        ```python
        @router.post("/admin/dangerous-operation")
        @require_admin_signature()
        async def dangerous_operation(request: Request):
            # Only accessible with admin key signature
            return {"status": "executed"}
        ```
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Find Request object
            request = None
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            for param_name, param_value in bound_args.arguments.items():
                if isinstance(param_value, Request):
                    request = param_value
                    break

            if not request:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found in endpoint parameters",
                )

            # First verify signature using the base decorator logic
            config = SignatureConfig()

            # Get Authorization header
            auth_header = request.headers.get("authorization", "")
            if not auth_header:
                error_msg = custom_error_message or "Admin signature required"
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=error_msg,
                )

            # Parse signature
            signature = parse_authorization_header(auth_header)
            if not signature or not signature.key_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid Authorization header format",
                )

            # Check if it's an admin key
            if not signature.key_id.startswith(admin_key_prefix):
                logger.warning(
                    "non_admin_key_used",
                    key_id=signature.key_id,
                    endpoint=func.__name__,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Admin signature required for this operation",
                )

            # Now verify the signature
            secret_key = signature_key_store.get_key(signature.key_id)
            if not secret_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Unknown admin key ID",
                )

            # Read body if needed
            body = None
            if config.include_body and request.method in ["POST", "PUT", "PATCH"]:
                if hasattr(request, "_body"):
                    body = request._body
                else:
                    body = await request.body()
                    request._body = body

            # Extract headers and query params
            headers = dict(request.headers)
            query_params = dict(request.query_params) if request.query_params else None

            # Verify signature
            result = verify_signature(
                secret_key=secret_key,
                method=request.method,
                path=request.url.path,
                headers=headers,
                provided_signature=signature,
                query_params=query_params,
                body=body,
                config=config,
                nonce_cache=set(nonce_cache._nonces.keys()) if hasattr(nonce_cache, "_nonces") else None,
            )

            if not result.is_valid:
                logger.warning(
                    "admin_signature_verification_failed",
                    endpoint=func.__name__,
                    key_id=signature.key_id,
                    error=result.error,
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Admin signature verification failed: {result.error}",
                )

            # Store signature info
            request.state.signature = signature
            request.state.signature_key_id = signature.key_id
            request.state.is_admin_request = True

            logger.info(
                "admin_signature_verified",
                endpoint=func.__name__,
                key_id=signature.key_id,
            )

            return await func(*args, **kwargs)

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            raise NotImplementedError("Admin signature decorator only supports async endpoints.")

    return decorator


def verify_webhook_signature(
    secret_key: str,
    signature_header: str = "X-Webhook-Signature",
    timestamp_header: str = "X-Webhook-Timestamp",
    max_age_seconds: int = 300,
) -> Callable[..., Any]:
    """Decorator to verify webhook signatures.

    Args:
        secret_key: Webhook secret key
        signature_header: Header containing signature
        timestamp_header: Header containing timestamp
        max_age_seconds: Maximum age for webhook

    Returns:
        Decorator function

    Example:
        ```python
        @router.post("/webhooks/payment")
        @verify_webhook_signature(secret_key=settings.PAYMENT_WEBHOOK_SECRET)
        async def payment_webhook(request: Request, data: PaymentWebhook):
            # Webhook signature verified
            return {"received": True}
        ```
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Find Request object
            request = None
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            for param_name, param_value in bound_args.arguments.items():
                if isinstance(param_value, Request):
                    request = param_value
                    break

            if not request:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found in endpoint parameters",
                )

            # Get signature and timestamp
            signature = request.headers.get(signature_header)
            timestamp = request.headers.get(timestamp_header)

            if not signature or not timestamp:
                logger.warning(
                    "webhook_headers_missing",
                    endpoint=func.__name__,
                    has_signature=bool(signature),
                    has_timestamp=bool(timestamp),
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Missing webhook signature headers",
                )

            # Verify timestamp
            try:
                timestamp_int = int(timestamp)
                current_time = int(time.time())
                age = current_time - timestamp_int

                if age > max_age_seconds:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Webhook timestamp too old",
                    )

                if age < -30:  # Allow 30s clock skew
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Webhook timestamp in future",
                    )

            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid webhook timestamp",
                )

            # Get request body
            if hasattr(request, "_body"):
                body = request._body
            else:
                body = await request.body()
                request._body = body

            # Create signature
            import hashlib
            import hmac

            # CodeQL [py/weak-sensitive-data-hashing] HMAC-SHA256 appropriate for request signature verification, not sensitive data storage
            expected_signature = hmac.new(
                secret_key.encode(),
                f"{timestamp}.{body.decode()}".encode(),
                hashlib.sha256,  # CodeQL [py/weak-sensitive-data-hashing] HMAC-SHA256 appropriate for request signatures
            ).hexdigest()

            # Verify signature
            if not hmac.compare_digest(signature, expected_signature):
                logger.warning(
                    "webhook_signature_invalid",
                    endpoint=func.__name__,
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid webhook signature",
                )

            logger.info(
                "webhook_signature_verified",
                endpoint=func.__name__,
                age=age,
            )

            return await func(*args, **kwargs)

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            raise NotImplementedError("Webhook signature decorator only supports async endpoints.")

    return decorator
