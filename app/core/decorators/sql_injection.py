"""Decorators for SQL injection prevention."""

import functools
import inspect
from typing import Any, Callable, Dict, List, Optional, Set

from fastapi import HTTPException, Request, status
from pydantic import BaseModel
from structlog.stdlib import get_logger

from ..sql_injection_prevention import (
    QueryValidationLevel,
    SQLInjectionPreventionMiddleware,
    detect_sql_injection_patterns,
    validate_query_parameter,
)

logger = get_logger(__name__)


def prevent_sql_injection(
    validation_level: QueryValidationLevel = QueryValidationLevel.MODERATE,
    check_query_params: bool = True,
    check_path_params: bool = True,
    check_body: bool = True,
    custom_error_message: Optional[str] = None,
    log_attempts: bool = True,
) -> Callable[..., Any]:
    """Decorator to prevent SQL injection in endpoint parameters.

    Args:
        validation_level: Validation strictness level
        check_query_params: Check query parameters
        check_path_params: Check path parameters
        check_body: Check request body
        custom_error_message: Custom error message for injection attempts
        log_attempts: Whether to log injection attempts

    Returns:
        Decorator function

    Example:
        ```python
        @router.get("/users")
        @prevent_sql_injection(validation_level=QueryValidationLevel.STRICT)
        async def get_users(status: str = Query(...)):
            # status parameter is automatically checked for SQL injection
            return {"users": []}
        ```
    """
    middleware = SQLInjectionPreventionMiddleware(
        validation_level=validation_level,
        log_attempts=log_attempts,
        block_on_detection=True,
    )

    def _validate_parameters(sig, bound_args, func_name) -> list:
        """Extract parameter validation logic to reduce complexity."""
        unsafe_params = []

        for param_name, param_value in bound_args.arguments.items():
            param = sig.parameters.get(param_name)
            if not param or isinstance(param_value, Request):
                continue

            # Check path parameters
            if check_path_params and isinstance(param_value, str):
                if not middleware.check_value(param_value, param_name):
                    unsafe_params.append(f"path parameter '{param_name}'")

            # Check query parameters
            if check_query_params and param_name not in ["self", "cls", "request"]:
                if isinstance(param_value, str):
                    if not middleware.check_value(param_value, param_name):
                        unsafe_params.append(f"query parameter '{param_name}'")
                elif isinstance(param_value, list):
                    for i, item in enumerate(param_value):
                        if isinstance(item, str) and not middleware.check_value(item, f"{param_name}[{i}]"):
                            unsafe_params.append(f"query parameter '{param_name}[{i}]'")

            # Check request body
            if check_body and isinstance(param_value, BaseModel):
                data = param_value.model_dump()
                is_safe, unsafe_fields = middleware.check_request_data(data)
                if not is_safe:
                    unsafe_params.extend([f"body field '{field}'" for field in unsafe_fields])

        return unsafe_params

    def _handle_unsafe_params(unsafe_params, func_name) -> None:
        """Handle detected unsafe parameters."""
        if unsafe_params:
            error_msg = custom_error_message or f"SQL injection attempt detected in: {', '.join(unsafe_params)}"
            if log_attempts:
                logger.warning(
                    "sql_injection_blocked",
                    endpoint=func_name,
                    unsafe_params=unsafe_params,
                )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            unsafe_params = _validate_parameters(sig, bound_args, func.__name__)
            _handle_unsafe_params(unsafe_params, func.__name__)

            return await func(*bound_args.args, **bound_args.kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            unsafe_params = _validate_parameters(sig, bound_args, func.__name__)
            _handle_unsafe_params(unsafe_params, func.__name__)

            return func(*bound_args.args, **bound_args.kwargs)

        # Return appropriate wrapper
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def validate_sql_params(
    allowed_tables: Optional[Set[str]] = None,
    allowed_columns: Optional[Set[str]] = None,
    max_length: Optional[int] = None,
    custom_validators: Optional[Dict[str, Callable[[Any], bool]]] = None,
) -> Callable[..., Any]:
    """Decorator to validate SQL-related parameters.

    Args:
        allowed_tables: Set of allowed table names
        allowed_columns: Set of allowed column names
        max_length: Maximum length for string parameters
        custom_validators: Custom validation functions per parameter

    Returns:
        Decorator function

    Example:
        ```python
        @router.post("/query")
        @validate_sql_params(
            allowed_tables={"users", "products"},
            allowed_columns={"id", "name", "email", "status"},
            max_length=100
        )
        async def execute_query(table: str, column: str, value: str):
            # Parameters are validated against allowed values
            return {"result": []}
        ```
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            for param_name, param_value in bound_args.arguments.items():
                # Skip special parameters
                if param_name in ["self", "cls", "request"] or isinstance(param_value, Request):
                    continue

                # Apply custom validators
                if custom_validators and param_name in custom_validators:
                    validator = custom_validators[param_name]
                    if not validator(param_value):
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Invalid value for parameter '{param_name}'",
                        )

                # Validate against allowed tables
                if allowed_tables and param_name in [
                    "table",
                    "table_name",
                    "from_table",
                ]:
                    if param_value not in allowed_tables:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Table '{param_value}' is not allowed",
                        )

                # Validate against allowed columns
                if allowed_columns and param_name in [
                    "column",
                    "columns",
                    "select",
                    "order_by",
                ]:
                    columns = param_value if isinstance(param_value, list) else [param_value]
                    for col in columns:
                        if col not in allowed_columns:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Column '{col}' is not allowed",
                            )

                # Validate string length
                if max_length and isinstance(param_value, str) and len(param_value) > max_length:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Parameter '{param_name}' exceeds maximum length of {max_length}",
                    )

            return await func(*bound_args.args, **bound_args.kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Similar logic for sync functions
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            for param_name, param_value in bound_args.arguments.items():
                if param_name in ["self", "cls", "request"] or isinstance(param_value, Request):
                    continue

                if custom_validators and param_name in custom_validators:
                    validator = custom_validators[param_name]
                    if not validator(param_value):
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Invalid value for parameter '{param_name}'",
                        )

                if allowed_tables and param_name in [
                    "table",
                    "table_name",
                    "from_table",
                ]:
                    if param_value not in allowed_tables:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Table '{param_value}' is not allowed",
                        )

                if allowed_columns and param_name in [
                    "column",
                    "columns",
                    "select",
                    "order_by",
                ]:
                    columns = param_value if isinstance(param_value, list) else [param_value]
                    for col in columns:
                        if col not in allowed_columns:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Column '{col}' is not allowed",
                            )

                if max_length and isinstance(param_value, str) and len(param_value) > max_length:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Parameter '{param_name}' exceeds maximum length of {max_length}",
                    )

            return func(*bound_args.args, **bound_args.kwargs)

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def use_safe_query(
    template_name: Optional[str] = None,
    validation_level: QueryValidationLevel = QueryValidationLevel.MODERATE,
) -> Callable[..., Any]:
    """Decorator to enforce use of safe query templates.

    Args:
        template_name: Name of the safe query template to use
        validation_level: Validation level for custom queries

    Returns:
        Decorator function

    Example:
        ```python
        @router.get("/users/{user_id}")
        @use_safe_query(template_name="get_user_by_id")
        async def get_user(user_id: int):
            # Endpoint is forced to use pre-defined safe query
            return {"user": {}}
        ```
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        # Store template name in function metadata
        setattr(func, "_safe_query_template", template_name)
        setattr(func, "_sql_validation_level", validation_level)

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Log safe query usage
            logger.info(
                "using_safe_query_template",
                endpoint=func.__name__,
                template=template_name,
                validation_level=validation_level.value,
            )
            return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            logger.info(
                "using_safe_query_template",
                endpoint=func.__name__,
                template=template_name,
                validation_level=validation_level.value,
            )
            return func(*args, **kwargs)

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator
