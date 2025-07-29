"""Example endpoint demonstrating field sanitization integration."""

from typing import Any, Dict

from appcore.field_sanitization import (
    COMMENT_SANITIZATION,
    EMAIL_SANITIZATION,
    USERNAME_SANITIZATION,
    FieldSanitizationRule,
    SanitizationLevel,
    SanitizationType,
    sanitize_request_data,
)

# Note: validate_request is not needed for this example
from appcore.rate_limiting import rate_limit
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from structlog.stdlib import get_logger

logger = get_logger(__name__)

router = APIRouter()


class UserProfileUpdate(BaseModel):
    """User profile update request."""

    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=5, max_length=254)
    bio: str = Field(..., max_length=1000)
    website: str = Field(..., max_length=2048)
    phone: str = Field(..., max_length=20)


class BlogPostCreate(BaseModel):
    """Blog post creation request."""

    title: str = Field(..., min_length=1, max_length=200)
    content: str = Field(..., min_length=1, max_length=50000)
    tags: list[str] = Field(default_factory=list)
    allow_comments: bool = Field(default=True)


class CommentCreate(BaseModel):
    """Comment creation request."""

    author_name: str = Field(..., min_length=1, max_length=100)
    author_email: str = Field(..., min_length=5, max_length=254)
    content: str = Field(..., min_length=1, max_length=1000)


# Define sanitization rules for each endpoint
PROFILE_UPDATE_RULES = [
    USERNAME_SANITIZATION,
    EMAIL_SANITIZATION,
    FieldSanitizationRule(
        field_name="bio",
        sanitization_types=[SanitizationType.HTML, SanitizationType.SQL],
        level=SanitizationLevel.MODERATE,
        max_length=1000,
        allow_html_tags={"p", "br", "strong", "em", "a"},
    ),
    FieldSanitizationRule(
        field_name="website",
        sanitization_types=[SanitizationType.URL],
        level=SanitizationLevel.STRICT,
        allow_url_schemes=["http", "https"],
    ),
    FieldSanitizationRule(
        field_name="phone",
        sanitization_types=[SanitizationType.PHONE],
        level=SanitizationLevel.MODERATE,
    ),
]

BLOG_POST_RULES = [
    FieldSanitizationRule(
        field_name="title",
        sanitization_types=[SanitizationType.HTML, SanitizationType.SQL],
        level=SanitizationLevel.STRICT,
        max_length=200,
        strip_html=True,  # No HTML in titles
    ),
    FieldSanitizationRule(
        field_name="content",
        sanitization_types=[SanitizationType.HTML, SanitizationType.SQL],
        level=SanitizationLevel.MODERATE,
        max_length=50000,
        allow_html_tags={
            "p",
            "br",
            "strong",
            "em",
            "u",
            "i",
            "b",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "ul",
            "ol",
            "li",
            "blockquote",
            "pre",
            "code",
            "a",
            "img",
        },
    ),
    FieldSanitizationRule(
        field_name="tags",
        sanitization_types=[SanitizationType.GENERAL],
        level=SanitizationLevel.STRICT,
        max_length=50,  # Per tag
        strip_html=True,
        strip_sql=True,
    ),
]

COMMENT_RULES = [
    FieldSanitizationRule(
        field_name="author_name",
        sanitization_types=[SanitizationType.GENERAL],
        level=SanitizationLevel.STRICT,
        max_length=100,
        strip_html=True,
    ),
    EMAIL_SANITIZATION,
    COMMENT_SANITIZATION,
]


@router.put("/profile")
@rate_limit("api")
async def update_profile(
    profile_data: UserProfileUpdate,
) -> Dict[str, Any]:
    """Update user profile with sanitized data.

    This endpoint demonstrates field-level sanitization for user profiles.
    Different fields have different sanitization rules:
    - Username: Alphanumeric only
    - Email: Valid email format
    - Bio: Limited HTML allowed
    - Website: Valid HTTP/HTTPS URLs only
    - Phone: Valid phone number format
    """
    try:
        # Convert Pydantic model to dict
        data = profile_data.model_dump()

        # Apply sanitization
        sanitized_data = sanitize_request_data(data, PROFILE_UPDATE_RULES)

        # Log sanitization results
        for field, original in data.items():
            if field in sanitized_data and sanitized_data[field] != original:
                logger.info(
                    "field_sanitized",
                    field=field,
                    original_length=len(str(original)),
                    sanitized_length=len(str(sanitized_data[field])),
                )

        # Validate sanitized data still meets requirements
        if not sanitized_data.get("username"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Username cannot be empty after sanitization"
            )

        if not sanitized_data.get("email"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Email cannot be empty after sanitization"
            )

        # Here you would save the sanitized data to database
        # For demo, just return the sanitized data
        return {
            "message": "Profile updated successfully",
            "sanitized_data": sanitized_data,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("profile_update_error", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update profile")


@router.post("/blog/posts")
@rate_limit("api")
async def create_blog_post(
    post_data: BlogPostCreate,
) -> Dict[str, Any]:
    """Create a blog post with sanitized content.

    This endpoint allows rich HTML content but sanitizes it to prevent:
    - XSS attacks through script injection
    - SQL injection in any field
    - Dangerous HTML tags while preserving formatting
    """
    try:
        # Convert to dict
        data = post_data.model_dump()

        # Special handling for tags array - sanitize each tag
        if "tags" in data and isinstance(data["tags"], list):
            # The sanitization framework will handle list items
            pass

        # Apply sanitization
        sanitized_data = sanitize_request_data(data, BLOG_POST_RULES)

        # Additional validation for sanitized content
        if not sanitized_data.get("title"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Title cannot be empty after sanitization"
            )

        if not sanitized_data.get("content"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Content cannot be empty after sanitization"
            )

        # Ensure tags are still valid after sanitization
        if "tags" in sanitized_data:
            sanitized_tags = []
            for tag in sanitized_data["tags"]:
                if isinstance(tag, str) and tag.strip():
                    sanitized_tags.append(tag.strip())
            sanitized_data["tags"] = sanitized_tags[:10]  # Limit to 10 tags

        return {
            "message": "Blog post created successfully",
            "post_id": "example-123",
            "sanitized_data": sanitized_data,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("blog_post_creation_error", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create blog post")


@router.post("/blog/posts/{post_id}/comments")
@rate_limit("api")
async def create_comment(
    post_id: str,
    comment_data: CommentCreate,
) -> Dict[str, Any]:
    """Create a comment with sanitized content.

    Comments have stricter sanitization rules:
    - Limited HTML tags allowed
    - Author name must be plain text
    - Email must be valid format
    - Content is sanitized for both HTML and SQL injection
    """
    try:
        # Validate post_id format
        if not post_id or len(post_id) > 50:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid post ID")

        # Convert to dict
        data = comment_data.model_dump()

        # Apply sanitization
        sanitized_data = sanitize_request_data(data, COMMENT_RULES)

        # Validate sanitized data
        if not sanitized_data.get("author_name"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Author name cannot be empty after sanitization"
            )

        if not sanitized_data.get("content"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Comment content cannot be empty after sanitization"
            )

        return {
            "message": "Comment created successfully",
            "post_id": post_id,
            "comment_id": "comment-456",
            "sanitized_data": sanitized_data,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("comment_creation_error", error=str(e), post_id=post_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create comment")


class ContactForm(BaseModel):
    """Contact form submission."""

    name: str = Field(..., min_length=1, max_length=100)
    email: str = Field(..., min_length=5, max_length=254)
    subject: str = Field(..., min_length=1, max_length=200)
    message: str = Field(..., min_length=1, max_length=5000)


@router.post("/contact")
@rate_limit("api")
async def submit_contact_form(
    contact_data: ContactForm,
) -> Dict[str, Any]:
    """Submit a contact form with sanitized data.

    This endpoint demonstrates inline sanitization.
    All fields are sanitized to prevent injection attacks.
    """
    try:
        # Convert to dict
        data = contact_data.model_dump()

        # Define sanitization rules
        contact_rules = [
            FieldSanitizationRule(
                field_name="name",
                sanitization_types=[SanitizationType.GENERAL],
                level=SanitizationLevel.STRICT,
                max_length=100,
                strip_html=True,
            ),
            EMAIL_SANITIZATION,
            FieldSanitizationRule(
                field_name="subject",
                sanitization_types=[SanitizationType.GENERAL],
                level=SanitizationLevel.STRICT,
                max_length=200,
                strip_html=True,
            ),
            FieldSanitizationRule(
                field_name="message",
                sanitization_types=[SanitizationType.HTML, SanitizationType.SQL],
                level=SanitizationLevel.MODERATE,
                max_length=5000,
                strip_html=True,  # Plain text only for contact forms
            ),
        ]

        # Apply sanitization
        sanitized_data = sanitize_request_data(data, contact_rules)

        # Validate all fields are present after sanitization
        for field in ["name", "email", "subject", "message"]:
            if not sanitized_data.get(field):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"{field.title()} cannot be empty after sanitization",
                )

        # Log contact form submission
        logger.info(
            "contact_form_submitted",
            email=sanitized_data["email"],
            subject_length=len(sanitized_data["subject"]),
        )

        return {
            "message": "Contact form submitted successfully",
            "ticket_id": "ticket-789",
            "sanitized_data": sanitized_data,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("contact_form_error", error=str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to submit contact form")
