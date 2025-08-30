"""Input sanitization dependencies for FastAPI.

This module provides dependency injection based sanitization,
which is more idiomatic for FastAPI than middleware-based approaches.
"""

import json
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel, field_validator, model_validator

from app.utils.sanitization import sanitize_dict, sanitize_string


class SanitizedBody:
    """Dependency that provides sanitized request body."""

    def __init__(self, strip_js: bool = True, max_length: int = 10000):
        self.strip_js = strip_js
        self.max_length = max_length

    async def __call__(self, request: Request) -> Any:
        """Get and sanitize the request body."""
        try:
            # Get the raw body
            body = await request.json()

            # Sanitize it
            if isinstance(body, dict):
                return self._sanitize_value(body)
            elif isinstance(body, list):
                return [self._sanitize_value(item) for item in body]
            else:
                return body

        except json.JSONDecodeError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON body")
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error processing request: {str(e)}",
            )

    def _sanitize_value(self, value: Any) -> Any:
        """Recursively sanitize values."""
        if isinstance(value, str):
            return sanitize_string(value, strip_js=self.strip_js, max_length=self.max_length)
        elif isinstance(value, dict):
            return {str(k): self._sanitize_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._sanitize_value(item) for item in value]
        else:
            return value


# Create default instances
get_sanitized_body = SanitizedBody(strip_js=True)
get_sanitized_body_no_js_strip = SanitizedBody(strip_js=False)


# Pydantic model with built-in sanitization
class SanitizedModel(BaseModel):
    """Base model that automatically sanitizes string fields."""

    class Config:
        # This ensures validators run even when assigning values
        validate_assignment = True

    @model_validator(mode="before")
    @classmethod
    def sanitize_strings(cls, values: Any) -> Any:
        """Sanitize all string fields."""
        if isinstance(values, dict):
            return {
                k: (sanitize_string(v, strip_js=True, max_length=10000) if isinstance(v, str) else v)
                for k, v in values.items()
            }
        elif isinstance(values, str):
            return sanitize_string(values, strip_js=True, max_length=10000)
        return values


# Example usage models
class UserInput(SanitizedModel):
    """Example user input model with automatic sanitization."""

    name: str
    email: str
    bio: Optional[str] = None


class MessageInput(SanitizedModel):
    """Example message model with automatic sanitization."""

    content: str
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("metadata")
    @classmethod
    def sanitize_metadata(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Sanitize metadata dictionary."""
        if v is not None:
            return sanitize_dict(v)
        return v


# Usage example:
# @app.post("/users")
# async def create_user(user: UserInput):
#     # user.name and user.email are already sanitized
#     return user
#
# @app.post("/raw-data")
# async def process_raw_data(data: Dict = Depends(get_sanitized_body)):
#     # data is sanitized
#     return data
