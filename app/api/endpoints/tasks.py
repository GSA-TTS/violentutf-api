"""Task management API endpoints."""

import logging
from datetime import datetime, timezone
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

# TECHNICAL DEBT: Direct SQLAlchemy usage violates Clean Architecture
# TODO: Move SQL queries to service layer
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_task_service
from app.core.auth import get_current_user
from app.models.task import Task, TaskResult, TaskStatus
from app.models.user import User
from app.schemas.task import (
    TaskBulkActionRequest,
    TaskBulkActionResponse,
    TaskCreate,
    TaskExecutionRequest,
    TaskExecutionResponse,
    TaskListResponse,
    TaskResponse,
    TaskResultListResponse,
    TaskResultResponse,
    TaskRetryRequest,
    TaskStatsResponse,
    TaskStatusUpdate,
    TaskUpdate,
)
from app.services.task_service import TaskService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/", response_model=TaskListResponse, summary="List tasks")
async def list_tasks(
    skip: int = Query(0, ge=0, description="Number of tasks to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Number of tasks to return"),
    status: Optional[TaskStatus] = Query(None, description="Filter by task status"),
    task_type: Optional[str] = Query(None, description="Filter by task type"),
    priority: Optional[str] = Query(None, description="Filter by priority"),
    created_by: Optional[str] = Query(None, description="Filter by creator"),
    task_service: TaskService = Depends(get_task_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TaskListResponse:
    """List tasks with filtering and pagination."""
    try:
        # Build query with filters
        query = select(Task).where(Task.is_deleted is False)

        if status:
            query = query.where(Task.status == status)
        if task_type:
            query = query.where(Task.task_type == task_type)
        if priority:
            query = query.where(Task.priority == priority)
        if created_by:
            query = query.where(Task.created_by == created_by)

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar() or 0

        # Apply pagination and ordering
        query = query.order_by(desc(Task.created_at)).offset(skip).limit(limit)

        # Execute query
        result = await db.execute(query)
        tasks = result.scalars().all()

        # Convert to response schemas
        task_responses = [TaskResponse.model_validate(task) for task in tasks]

        return TaskListResponse(
            tasks=task_responses,
            total=total,
            page=(skip // limit) + 1,
            per_page=limit,
            has_next=(skip + limit) < total,
        )

    except Exception as e:
        logger.error(f"Error listing tasks: {e}")
        raise HTTPException(status_code=500, detail="Failed to list tasks")


@router.post("/", response_model=TaskResponse, summary="Create task")
async def create_task(
    task_data: TaskCreate,
    task_service: TaskService = Depends(get_task_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TaskResponse:
    """Create a new task."""
    try:
        # Create task instance
        task = Task(
            name=task_data.name,
            task_type=task_data.task_type,
            description=task_data.description,
            priority=task_data.priority,
            input_data=task_data.input_data,
            config=task_data.config,
            max_retries=task_data.max_retries,
            webhook_url=task_data.webhook_url,
            webhook_secret=task_data.webhook_secret,
            created_by=current_user.username,
        )

        # Save to database
        db.add(task)
        # Service layer handles transactions automatically
        await db.refresh(task)

        logger.info(f"User {current_user.username} created task: {task.name}")

        return TaskResponse.model_validate(task)

    except Exception as e:
        logger.error(f"Error creating task: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to create task")


@router.get("/{task_id}", response_model=TaskResponse, summary="Get task")
async def get_task(
    task_id: str,
    task_service: TaskService = Depends(get_task_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TaskResponse:
    """Get a specific task by ID."""
    try:
        # Query task
        query = select(Task).where(and_(Task.id == task_id, Task.is_deleted is False))
        result = await db.execute(query)
        task = result.scalar_one_or_none()

        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        return TaskResponse.model_validate(task)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting task {task_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get task")


@router.put("/{task_id}", response_model=TaskResponse, summary="Update task")
async def update_task(
    task_id: str,
    task_data: TaskUpdate,
    task_service: TaskService = Depends(get_task_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TaskResponse:
    """Update a task."""
    try:
        # Get task
        query = select(Task).where(and_(Task.id == task_id, Task.is_deleted is False))
        result = await db.execute(query)
        task = result.scalar_one_or_none()

        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        # Check if task can be updated
        if task.status in [TaskStatus.RUNNING, TaskStatus.COMPLETED]:
            raise HTTPException(status_code=400, detail="Cannot update task that is running or completed")

        # Update fields
        update_data = task_data.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(task, field, value)

        task.updated_by = current_user.username

        # Service layer handles transactions automatically
        await db.refresh(task)

        logger.info(f"User {current_user.username} updated task: {task.name}")

        return TaskResponse.model_validate(task)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating task {task_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to update task")


@router.delete("/{task_id}", summary="Delete task")
async def delete_task(
    task_id: str,
    task_service: TaskService = Depends(get_task_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, str]:
    """Delete a task (soft delete)."""
    try:
        # Get task
        query = select(Task).where(and_(Task.id == task_id, Task.is_deleted is False))
        result = await db.execute(query)
        task = result.scalar_one_or_none()

        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        # Check if task can be deleted
        if task.status == TaskStatus.RUNNING:
            raise HTTPException(status_code=400, detail="Cannot delete running task. Cancel it first.")

        # Soft delete
        task.soft_delete(deleted_by=current_user.username)

        # Service layer handles transactions automatically

        logger.info(f"User {current_user.username} deleted task: {task.name}")

        return {"message": "Task deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting task {task_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to delete task")


@router.post("/{task_id}/execute", response_model=TaskExecutionResponse, summary="Execute task")
async def execute_task(
    task_id: str,
    execution_request: Optional[TaskExecutionRequest] = None,
    task_service: TaskService = Depends(get_task_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TaskExecutionResponse:
    """Execute a task asynchronously."""
    try:
        # Get task
        query = select(Task).where(and_(Task.id == task_id, Task.is_deleted is False))
        result = await db.execute(query)
        task = result.scalar_one_or_none()

        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        # Check if task can be executed
        if task.status in [TaskStatus.RUNNING]:
            raise HTTPException(status_code=400, detail="Task is already running")

        # Update task status
        task.status = TaskStatus.PENDING
        task.progress = 0
        task.progress_message = "Queued for execution"
        task.started_at = datetime.now(timezone.utc)
        task.updated_by = current_user.username

        # Dispatch to Celery worker
        from app.celery.tasks import execute_task

        config_override = execution_request.config_override if execution_request else {}
        celery_task = execute_task.delay(task_id, config_override)
        task.celery_task_id = celery_task.id

        # Service layer handles transactions automatically
        await db.refresh(task)

        logger.info(f"User {current_user.username} executed task: {task.name}")

        return TaskExecutionResponse(
            task_id=task.id,
            execution_id=None,  # Will be set when task is executed by orchestrator
            status=task.status,
            started_at=task.started_at,
            celery_task_id=task.celery_task_id,
            status_url=f"/api/v1/tasks/{task.id}",
            webhook_configured=task.webhook_url is not None,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error executing task {task_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to execute task")


@router.post("/{task_id}/cancel", summary="Cancel task")
async def cancel_task(
    task_id: str,
    task_service: TaskService = Depends(get_task_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, str]:
    """Cancel a running task."""
    try:
        # Get task
        query = select(Task).where(and_(Task.id == task_id, Task.is_deleted is False))
        result = await db.execute(query)
        task = result.scalar_one_or_none()

        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        # Check if task can be cancelled
        if task.status not in [TaskStatus.PENDING, TaskStatus.RUNNING]:
            raise HTTPException(status_code=400, detail="Can only cancel pending or running tasks")

        # Cancel task
        task.status = TaskStatus.CANCELLED
        task.completed_at = datetime.now(timezone.utc)
        task.progress_message = "Task cancelled by user"
        task.updated_by = current_user.username

        # Cancel Celery task
        if task.celery_task_id:
            from app.celery.celery import celery_app

            celery_app.control.revoke(task.celery_task_id, terminate=True)

        # Service layer handles transactions automatically

        logger.info(f"User {current_user.username} cancelled task: {task.name}")

        return {"message": "Task cancelled successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling task {task_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to cancel task")


@router.post("/{task_id}/retry", response_model=TaskExecutionResponse, summary="Retry task")
async def retry_task(
    task_id: str,
    retry_request: TaskRetryRequest,
    task_service: TaskService = Depends(get_task_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TaskExecutionResponse:
    """Retry a failed task."""
    try:
        # Get task
        query = select(Task).where(and_(Task.id == task_id, Task.is_deleted is False))
        result = await db.execute(query)
        task = result.scalar_one_or_none()

        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        # Check if task can be retried
        if task.status not in [TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.TIMEOUT]:
            raise HTTPException(status_code=400, detail="Can only retry failed, cancelled, or timed out tasks")

        # Check retry limit
        if not retry_request.reset_retry_count and task.retry_count >= task.max_retries:
            raise HTTPException(status_code=400, detail="Maximum retry attempts exceeded")

        # Reset task for retry
        task.status = TaskStatus.PENDING
        task.progress = 0
        task.progress_message = "Queued for retry"
        task.started_at = datetime.now(timezone.utc)
        task.completed_at = None
        task.error_message = None
        task.error_details = None
        task.updated_by = current_user.username

        if retry_request.reset_retry_count:
            task.retry_count = 0
        else:
            task.retry_count += 1

        # Apply config overrides
        if retry_request.config_override:
            task.config.update(retry_request.config_override)

        # Dispatch to Celery worker for retry
        from app.celery.tasks import execute_task

        config_override = retry_request.config_override or {}
        celery_task = execute_task.delay(task_id, config_override)
        task.celery_task_id = celery_task.id

        # Service layer handles transactions automatically
        await db.refresh(task)

        logger.info(f"User {current_user.username} retried task: {task.name}")

        return TaskExecutionResponse(
            task_id=task.id,
            execution_id=task.id,
            status=task.status,
            started_at=task.started_at,
            celery_task_id=task.celery_task_id,
            status_url=f"/api/v1/tasks/{task.id}",
            webhook_configured=task.webhook_url is not None,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrying task {task_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to retry task")


@router.patch("/{task_id}/status", summary="Update task status")
async def update_task_status(  # noqa: C901
    task_id: str,
    status_update: TaskStatusUpdate,
    task_service: TaskService = Depends(get_task_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, str]:
    """Update task status (primarily for worker processes)."""
    try:
        # Get task
        query = select(Task).where(and_(Task.id == task_id, Task.is_deleted is False))
        result = await db.execute(query)
        task = result.scalar_one_or_none()

        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        # Update status and related fields
        task.status = status_update.status

        if status_update.progress is not None:
            task.progress = status_update.progress

        if status_update.progress_message:
            task.progress_message = status_update.progress_message

        if status_update.output_data:
            task.output_data = status_update.output_data

        if status_update.error_message:
            task.error_message = status_update.error_message

        if status_update.error_details:
            task.error_details = status_update.error_details

        # Set completion time for final states
        if status_update.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
            task.completed_at = datetime.now(timezone.utc)

        task.updated_by = current_user.username

        # Service layer handles transactions automatically

        return {"message": "Task status updated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating task status {task_id}: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to update task status")


@router.get("/{task_id}/results", response_model=TaskResultListResponse, summary="Get task results")
async def get_task_results(
    task_id: str,
    result_type: Optional[str] = Query(None, description="Filter by result type"),
    task_service: TaskService = Depends(get_task_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TaskResultListResponse:
    """Get results for a specific task."""
    try:
        # Verify task exists
        task_query = select(Task).where(and_(Task.id == task_id, Task.is_deleted is False))
        task_result = await db.execute(task_query)
        task = task_result.scalar_one_or_none()

        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        # Query results
        query = select(TaskResult).where(TaskResult.task_id == task_id)

        if result_type:
            query = query.where(TaskResult.result_type == result_type)

        query = query.order_by(desc(TaskResult.created_at))

        result = await db.execute(query)
        results = result.scalars().all()

        # Convert to response schemas
        result_responses = [TaskResultResponse.model_validate(r) for r in results]

        return TaskResultListResponse(
            results=result_responses,
            total=len(result_responses),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting task results {task_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get task results")


@router.get("/stats", response_model=TaskStatsResponse, summary="Get task statistics")
async def get_task_stats(
    task_service: TaskService = Depends(get_task_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TaskStatsResponse:
    """Get task execution statistics."""
    try:
        # Get counts by status
        status_counts = {}
        for status in TaskStatus:
            count_query = select(func.count()).where(and_(Task.status == status, Task.is_deleted is False))
            result = await db.execute(count_query)
            status_counts[status.value] = result.scalar() or 0

        # Calculate success rate
        total_completed = status_counts.get("completed", 0) + status_counts.get("failed", 0)
        success_rate = None
        if total_completed > 0:
            success_rate = status_counts.get("completed", 0) / total_completed

        # TODO: Calculate average execution time
        avg_execution_time = None

        return TaskStatsResponse(
            total_tasks=sum(status_counts.values()),
            pending_tasks=status_counts.get("pending", 0),
            running_tasks=status_counts.get("running", 0),
            completed_tasks=status_counts.get("completed", 0),
            failed_tasks=status_counts.get("failed", 0),
            cancelled_tasks=status_counts.get("cancelled", 0),
            avg_execution_time=avg_execution_time,
            success_rate=success_rate,
        )

    except Exception as e:
        logger.error(f"Error getting task stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get task statistics")


@router.post("/bulk-action", response_model=TaskBulkActionResponse, summary="Bulk task actions")
async def bulk_task_action(
    action_request: TaskBulkActionRequest,
    task_service: TaskService = Depends(get_task_service),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TaskBulkActionResponse:
    """Perform bulk actions on multiple tasks."""
    try:
        # Get tasks
        query = select(Task).where(and_(Task.id.in_(action_request.task_ids), Task.is_deleted is False))
        result = await db.execute(query)
        tasks = result.scalars().all()

        successful = 0
        failed = 0
        errors = []
        results = []

        for task in tasks:
            try:
                if action_request.action == "cancel":
                    if task.status in [TaskStatus.PENDING, TaskStatus.RUNNING]:
                        task.status = TaskStatus.CANCELLED
                        task.completed_at = datetime.now(timezone.utc)
                        task.updated_by = current_user.username
                        successful += 1
                        results.append({"task_id": task.id, "status": "cancelled"})
                    else:
                        failed += 1
                        errors.append({"task_id": task.id, "error": "Task cannot be cancelled in current state"})

                elif action_request.action == "delete":
                    if task.status != TaskStatus.RUNNING:
                        task.soft_delete(deleted_by=current_user.username)
                        successful += 1
                        results.append({"task_id": task.id, "status": "deleted"})
                    else:
                        failed += 1
                        errors.append({"task_id": task.id, "error": "Cannot delete running task"})

                else:
                    failed += 1
                    errors.append({"task_id": task.id, "error": f"Unknown action: {action_request.action}"})

            except Exception as e:
                failed += 1
                errors.append({"task_id": task.id, "error": str(e)})

        # Service layer handles transactions automatically

        logger.info(
            f"User {current_user.username} performed bulk action "
            f"{action_request.action} on {len(action_request.task_ids)} tasks"
        )

        return TaskBulkActionResponse(
            total_requested=len(action_request.task_ids),
            successful=successful,
            failed=failed,
            errors=errors,
            results=results,
        )

    except Exception as e:
        logger.error(f"Error performing bulk task action: {e}")
        # Service layer handles rollback
        raise HTTPException(status_code=500, detail="Failed to perform bulk action")
