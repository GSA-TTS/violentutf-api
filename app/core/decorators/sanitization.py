"""Decorators for field sanitization."""

import functools
import inspect
from typing import Any, Callable, List, Optional, Union

from fastapi import HTTPException, Request, status
from pydantic import BaseModel
from structlog.stdlib import get_logger

from ..field_sanitization import (
    FieldSanitizationRule,
    SanitizationConfig,
    SanitizationLevel,
    SanitizationType,
    sanitize_request_data,
)

logger = get_logger(__name__)


def sanitize_request(
    rules: List[FieldSanitizationRule],
    config: Optional[SanitizationConfig] = None,
    validate_after: bool = True,
) -> Callable[..., Any]:
    """Decorator to automatically sanitize request data.

    Args:
        rules: List of sanitization rules to apply
        config: Sanitization configuration
        validate_after: Whether to validate data after sanitization

    Returns:
        Decorator function

    Example:
        ```python
        @router.post("/users")
        @sanitize_request([USERNAME_SANITIZATION, EMAIL_SANITIZATION])
        async def create_user(user_data: UserCreate):
            # user_data will be automatically sanitized
            return {"user_id": "123"}
        ```
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get function signature
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            # Find Pydantic models in arguments
            for param_name, param_value in bound_args.arguments.items():
                if isinstance(param_value, BaseModel):
                    try:
                        # Convert model to dict
                        data = param_value.model_dump()

                        # Apply sanitization
                        sanitized_data = sanitize_request_data(data, rules, config)

                        # Log sanitization
                        changes = []
                        for field, original in data.items():
                            if field in sanitized_data and sanitized_data[field] != original:
                                changes.append(field)

                        if changes:
                            logger.info(
                                "request_data_sanitized",
                                endpoint=func.__name__,
                                fields_changed=changes,
                            )

                        # Update the model with sanitized data
                        # Create new instance to maintain immutability
                        model_class = type(param_value)
                        sanitized_model = model_class(**sanitized_data)

                        # Validate if requested
                        if validate_after:
                            # Pydantic will validate during construction
                            pass

                        # Replace argument with sanitized version
                        bound_args.arguments[param_name] = sanitized_model

                    except Exception as e:
                        logger.error(
                            "sanitization_decorator_error",
                            error=str(e),
                            param_name=param_name,
                            endpoint=func.__name__,
                        )
                        if config and config.fail_on_error:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Failed to sanitize request data: {str(e)}",
                            )

                # Handle Request object for form data
                elif isinstance(param_value, Request):
                    # Skip Request objects - they need special handling
                    pass

            # Call original function with sanitized arguments
            return await func(*bound_args.args, **bound_args.kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Similar logic for sync functions
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            for param_name, param_value in bound_args.arguments.items():
                if isinstance(param_value, BaseModel):
                    try:
                        data = param_value.model_dump()
                        sanitized_data = sanitize_request_data(data, rules, config)

                        model_class = type(param_value)
                        sanitized_model = model_class(**sanitized_data)
                        bound_args.arguments[param_name] = sanitized_model

                    except Exception as e:
                        logger.error(
                            "sanitization_decorator_error",
                            error=str(e),
                            param_name=param_name,
                            endpoint=func.__name__,
                        )
                        if config and config.fail_on_error:
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Failed to sanitize request data: {str(e)}",
                            )

            return func(*bound_args.args, **bound_args.kwargs)

        # Return appropriate wrapper based on function type
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def sanitize_fields(**field_rules: Union[FieldSanitizationRule, List[SanitizationType], str]) -> Callable[..., Any]:
    """Decorator to sanitize specific fields with inline rules.

    Args:
        **field_rules: Field names mapped to sanitization rules

    Returns:
        Decorator function

    Example:
        ```python
        @router.post("/contact")
        @sanitize_fields(
            name=[SanitizationType.GENERAL],
            email=EMAIL_SANITIZATION,
            message=[SanitizationType.HTML, SanitizationType.SQL]
        )
        async def contact_form(data: ContactForm):
            return {"success": True}
        ```
    """
    # Convert field rules to FieldSanitizationRule objects
    rules = []
    for field_name, rule_spec in field_rules.items():
        if isinstance(rule_spec, FieldSanitizationRule):
            # Already a rule, just ensure field name matches
            rule = rule_spec
            rule.field_name = field_name
            rules.append(rule)
        elif isinstance(rule_spec, list):
            # List of sanitization types
            rules.append(
                FieldSanitizationRule(
                    field_name=field_name,
                    sanitization_types=rule_spec,
                )
            )
        elif isinstance(rule_spec, str):
            # Single sanitization type as string
            rules.append(
                FieldSanitizationRule(
                    field_name=field_name,
                    sanitization_types=[SanitizationType(rule_spec)],
                )
            )

    return sanitize_request(rules)


def auto_sanitize(
    level: Optional[str] = None,
    exclude_fields: Optional[List[str]] = None,
) -> Callable[..., Any]:
    """Decorator to automatically sanitize all string fields.

    Args:
        level: Default sanitization level (strict, moderate, lenient)
        exclude_fields: Fields to exclude from sanitization

    Returns:
        Decorator function

    Example:
        ```python
        @router.post("/data")
        @auto_sanitize(level="moderate", exclude_fields=["password", "api_key"])
        async def process_data(data: DataModel):
            return {"processed": True}
        ```
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            exclude = set(exclude_fields or [])

            for param_name, param_value in bound_args.arguments.items():
                if isinstance(param_value, BaseModel):
                    try:
                        data = param_value.model_dump()

                        # Create rules for all string fields
                        rules = []
                        for field_name, field_value in data.items():
                            if field_name not in exclude and isinstance(field_value, str):
                                rules.append(
                                    FieldSanitizationRule(
                                        field_name=field_name,
                                        sanitization_types=[SanitizationType.GENERAL],
                                        level=SanitizationLevel(level or "moderate"),
                                    )
                                )

                        if rules:
                            # Apply sanitization
                            sanitized_data = sanitize_request_data(data, rules)

                            # Create new model instance
                            model_class = type(param_value)
                            sanitized_model = model_class(**sanitized_data)
                            bound_args.arguments[param_name] = sanitized_model

                            logger.info(
                                "auto_sanitization_applied",
                                endpoint=func.__name__,
                                fields_sanitized=len(rules),
                            )

                    except Exception as e:
                        logger.error(
                            "auto_sanitization_error",
                            error=str(e),
                            endpoint=func.__name__,
                        )

            return await func(*bound_args.args, **bound_args.kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Similar logic for sync functions
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            exclude = set(exclude_fields or [])

            for param_name, param_value in bound_args.arguments.items():
                if isinstance(param_value, BaseModel):
                    try:
                        data = param_value.model_dump()

                        rules = []
                        for field_name, field_value in data.items():
                            if field_name not in exclude and isinstance(field_value, str):
                                rules.append(
                                    FieldSanitizationRule(
                                        field_name=field_name,
                                        sanitization_types=[SanitizationType.GENERAL],
                                        level=SanitizationLevel(level or "moderate"),
                                    )
                                )

                        if rules:
                            sanitized_data = sanitize_request_data(data, rules)
                            model_class = type(param_value)
                            sanitized_model = model_class(**sanitized_data)
                            bound_args.arguments[param_name] = sanitized_model

                    except Exception as e:
                        logger.error(
                            "auto_sanitization_error",
                            error=str(e),
                            endpoint=func.__name__,
                        )

            return func(*bound_args.args, **bound_args.kwargs)

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator
