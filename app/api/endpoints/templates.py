"""Report template management API endpoints."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

# TECHNICAL DEBT: Direct SQLAlchemy usage violates Clean Architecture
# TODO: Move SQL queries to service layer
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_template_service
from app.core.auth import get_current_user
from app.models.report import ReportTemplate, TemplateType
from app.models.user import User
from app.schemas.report import (
    ReportTemplateCreate,
    ReportTemplateListResponse,
    ReportTemplateResponse,
    ReportTemplateUpdate,
)
from app.services.template_service import TemplateService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/", response_model=ReportTemplateListResponse, summary="List templates")
async def list_templates(
    skip: int = Query(0, ge=0, description="Number of templates to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Number of templates to return"),
    template_type: Optional[TemplateType] = Query(None, description="Filter by template type"),
    category: Optional[str] = Query(None, description="Filter by category"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    is_featured: Optional[bool] = Query(None, description="Filter by featured status"),
    created_by: Optional[str] = Query(None, description="Filter by creator"),
    template_service: TemplateService = Depends(get_template_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportTemplateListResponse:
    """List templates with filtering and pagination."""
    try:
        # Build query with filters
        query = select(ReportTemplate).where(ReportTemplate.is_deleted.is_(False))

        if template_type:
            query = query.where(ReportTemplate.template_type == template_type)
        if category:
            query = query.where(ReportTemplate.category == category)
        if is_active is not None:
            query = query.where(ReportTemplate.is_active == is_active)
        if is_featured is not None:
            query = query.where(ReportTemplate.is_featured == is_featured)
        if created_by:
            query = query.where(ReportTemplate.created_by == created_by)

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar() or 0

        # Apply pagination and ordering (featured first, then by usage)
        query = (
            query.order_by(
                desc(ReportTemplate.is_featured),
                desc(ReportTemplate.usage_count),
                desc(ReportTemplate.created_at),
            )
            .offset(skip)
            .limit(limit)
        )

        # Execute query
        result = await db.execute(query)
        templates = result.scalars().all()

        # Convert to response schemas
        template_responses = [ReportTemplateResponse.model_validate(template) for template in templates]

        return ReportTemplateListResponse(
            templates=template_responses,
            total=total,
            page=(skip // limit) + 1,
            per_page=limit,
            has_next=(skip + limit) < total,
        )

    except Exception as e:
        logger.error(f"Error listing templates: {e}")
        raise HTTPException(status_code=500, detail="Failed to list templates")


@router.post(
    "/",
    response_model=ReportTemplateResponse,
    summary="Create template",
    status_code=201,
)
async def create_template(
    template_data: ReportTemplateCreate,
    template_service: TemplateService = Depends(get_template_service),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ReportTemplateResponse:
    """Create a new report template."""
    try:
        # Check if template name already exists
        existing_query = select(ReportTemplate).where(
            and_(
                ReportTemplate.name == template_data.name,
                ReportTemplate.is_deleted.is_(False),
            )
        )
        existing_result = await db.execute(existing_query)
        existing_template = existing_result.scalar_one_or_none()

        if existing_template:
            raise HTTPException(status_code=409, detail="Template with this name already exists")

        # Create template instance
        template = ReportTemplate(
            name=template_data.name,
            display_name=template_data.display_name,
            description=template_data.description,
            template_type=template_data.template_type,
            supported_formats=template_data.supported_formats or [],
            template_content=template_data.template_content or {},
            default_config=template_data.default_config or {},
            sections=template_data.sections or [],
            fields=template_data.fields or [],
            styles=template_data.styles or {},
            layout=template_data.layout or {},
            template_version_str=template_data.template_version_str,
            schema_version=template_data.schema_version,
            category=template_data.category,
            tags=template_data.tags or [],
            is_active=template_data.is_active,
            is_featured=template_data.is_featured,
            created_by=current_user.username,
        )

        # Save template to database
        db.add(template)
        # Service layer handles commit
        await db.refresh(template)

        logger.info(f"User {current_user.username} created template: {template.name}")

        return ReportTemplateResponse.model_validate(template)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating template: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to create template")


@router.get("/{template_id}", response_model=ReportTemplateResponse, summary="Get template")
async def get_template(
    template_id: str,
    template_service: TemplateService = Depends(get_template_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportTemplateResponse:
    """Get a specific template by ID."""
    try:
        # Query template
        query = select(ReportTemplate).where(
            and_(ReportTemplate.id == template_id, ReportTemplate.is_deleted.is_(False))
        )
        result = await db.execute(query)
        template = result.scalar_one_or_none()

        if not template:
            raise HTTPException(status_code=404, detail="Template not found")

        return ReportTemplateResponse.model_validate(template)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting template {template_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get template")


@router.put("/{template_id}", response_model=ReportTemplateResponse, summary="Update template")
async def update_template(
    template_id: str,
    template_data: ReportTemplateUpdate,
    template_service: TemplateService = Depends(get_template_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportTemplateResponse:
    """Update a template."""
    try:
        # Get template
        query = select(ReportTemplate).where(
            and_(ReportTemplate.id == template_id, ReportTemplate.is_deleted.is_(False))
        )
        result = await db.execute(query)
        template = result.scalar_one_or_none()

        if not template:
            raise HTTPException(status_code=404, detail="Template not found")

        # Update fields
        update_data = template_data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(template, field, value)

        template.updated_by = current_user.username

        # Service layer handles commit
        await db.refresh(template)

        logger.info(f"User {current_user.username} updated template: {template.name}")

        return ReportTemplateResponse.model_validate(template)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating template {template_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to update template")


@router.delete("/{template_id}", summary="Delete template")
async def delete_template(
    template_id: str,
    template_service: TemplateService = Depends(get_template_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, str]:
    """Delete a template (soft delete)."""
    try:
        # Get template
        query = select(ReportTemplate).where(
            and_(ReportTemplate.id == template_id, ReportTemplate.is_deleted.is_(False))
        )
        result = await db.execute(query)
        template = result.scalar_one_or_none()

        if not template:
            raise HTTPException(status_code=404, detail="Template not found")

        # Check if template is being used
        from app.models.report import Report

        usage_query = select(func.count()).where(and_(Report.template_id == template_id, Report.is_deleted.is_(False)))
        usage_result = await db.execute(usage_query)
        usage_count = usage_result.scalar() or 0

        if usage_count > 0:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete template that is used by {usage_count} report(s)",
            )

        # Soft delete
        template.soft_delete(deleted_by=current_user.username)

        # Service layer handles commit

        logger.info(f"User {current_user.username} deleted template: {template.name}")

        return {"message": "Template deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting template {template_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to delete template")


@router.post(
    "/{template_id}/clone",
    response_model=ReportTemplateResponse,
    summary="Clone template",
    status_code=201,
)
async def clone_template(
    template_id: str,
    new_name: str = Query(..., min_length=1, max_length=255, description="New template name"),
    template_service: TemplateService = Depends(get_template_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportTemplateResponse:
    """Clone an existing template."""
    try:
        # Get source template
        query = select(ReportTemplate).where(
            and_(ReportTemplate.id == template_id, ReportTemplate.is_deleted.is_(False))
        )
        result = await db.execute(query)
        source_template = result.scalar_one_or_none()

        if not source_template:
            raise HTTPException(status_code=404, detail="Template not found")

        # Check if new name already exists
        existing_query = select(ReportTemplate).where(
            and_(ReportTemplate.name == new_name, ReportTemplate.is_deleted.is_(False))
        )
        existing_result = await db.execute(existing_query)
        existing_template = existing_result.scalar_one_or_none()

        if existing_template:
            raise HTTPException(status_code=409, detail="Template with this name already exists")

        # Create cloned template
        cloned_template = ReportTemplate(
            name=new_name,
            display_name=f"{source_template.display_name} (Copy)",
            description=source_template.description,
            template_type=source_template.template_type,
            supported_formats=source_template.supported_formats.copy(),
            template_content=source_template.template_content.copy(),
            default_config=source_template.default_config.copy(),
            sections=[section.copy() for section in source_template.sections],
            fields=[field.copy() for field in source_template.fields],
            styles=source_template.styles.copy(),
            layout=source_template.layout.copy(),
            template_version_str=source_template.template_version_str,
            schema_version=source_template.schema_version,
            category=source_template.category,
            tags=source_template.tags.copy(),
            is_active=True,
            is_featured=False,  # Cloned templates are not featured by default
            created_by=current_user.username,
        )

        # Save cloned template to database
        db.add(cloned_template)
        # Service layer handles commit
        await db.refresh(cloned_template)

        logger.info(f"User {current_user.username} cloned template: {source_template.name} -> {new_name}")

        return ReportTemplateResponse.model_validate(cloned_template)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cloning template {template_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to clone template")


@router.get("/categories", summary="Get template categories")
async def get_template_categories(
    template_service: TemplateService = Depends(get_template_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, List[str]]:
    """Get all template categories and their available types."""
    try:
        # Get unique categories
        category_query = select(ReportTemplate.category.distinct()).where(
            and_(ReportTemplate.is_deleted.is_(False), ReportTemplate.is_active.is_(True))
        )
        category_result = await db.execute(category_query)
        categories = [cat[0] for cat in category_result.fetchall()]

        # Get available template types
        template_types = [t.value for t in TemplateType]

        return {"categories": categories, "template_types": template_types}

    except Exception as e:
        logger.error(f"Error getting template categories: {e}")
        raise HTTPException(status_code=500, detail="Failed to get template categories")


@router.post("/{template_id}/preview", summary="Preview template")
async def preview_template(
    template_id: str,
    sample_data: Dict[str, Any] = None,
    template_service: TemplateService = Depends(get_template_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Preview a template with sample data."""
    try:
        # Get template
        query = select(ReportTemplate).where(
            and_(ReportTemplate.id == template_id, ReportTemplate.is_deleted.is_(False))
        )
        result = await db.execute(query)
        template = result.scalar_one_or_none()

        if not template:
            raise HTTPException(status_code=404, detail="Template not found")

        # Generate preview using template content
        preview_data = {
            "template_id": template.id,
            "template_name": template.name,
            "template_content": template.template_content,
            "sections": template.sections,
            "fields": template.fields,
            "styles": template.styles,
            "layout": template.layout,
            "sample_data": sample_data or {},
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "supported_formats": template.supported_formats,
        }

        # Update last_used_at
        template.last_used_at = datetime.now(timezone.utc)
        # Service layer handles commit

        return preview_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error previewing template {template_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to preview template")
