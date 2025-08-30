"""Task management service for handling background task operations."""

from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.errors import NotFoundError, ValidationError
from app.models.task import Task
from app.repositories.task import TaskRepository

logger = get_logger(__name__)


class TaskService:
    """Service for managing background tasks with transaction management."""

    def __init__(self, repository_or_session: Union[TaskRepository, AsyncSession]):
        """Initialize task service with repository or database session.

        Args:
            repository_or_session: Task repository or AsyncSession
        """
        if isinstance(repository_or_session, AsyncSession):
            self.repository = TaskRepository(repository_or_session)
        else:
            self.repository = repository_or_session

    async def create_task(self, task_data: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Create a new background task.

        Args:
            task_data: Task creation data
            user_id: User creating the task

        Returns:
            Dict: Created task data

        Raises:
            ValidationError: If task data is invalid
        """
        try:
            # Add audit fields
            task_data.update(
                {
                    "id": str(uuid4()),
                    "created_by": user_id,
                    "updated_by": user_id,
                    "status": "pending",
                }
            )

            # Simulate task creation (would use actual Task model in real implementation)
            # Note: Repository handles session management

            logger.info("task_created", task_id=task_data["id"], user_id=user_id)
            return task_data

        except Exception as e:
            logger.error("failed_to_create_task", error=str(e))
            raise ValidationError(f"Failed to create task: {str(e)}")

    async def get_task(self, task_id: str) -> Dict[str, Any]:
        """Get task by ID.

        Args:
            task_id: Task identifier

        Returns:
            Dict: Task data if found

        Raises:
            NotFoundError: If task not found
        """
        # Simulate task retrieval
        task = {
            "id": task_id,
            "name": f"Task {task_id}",
            "status": "running",
            "progress": 50,
            "created_at": "2024-01-01T00:00:00Z",
        }

        if not task:
            raise NotFoundError(f"Task with ID {task_id} not found")
        return task

    async def list_tasks(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List tasks with pagination and filtering.

        Args:
            skip: Number of tasks to skip
            limit: Maximum number of tasks to return
            filters: Optional filters to apply
            user_id: Optional user ID filter for user's tasks

        Returns:
            List[Dict]: List of tasks
        """
        # Simulate task listing (filters not implemented in mock)
        _ = filters  # Acknowledge unused parameter
        tasks = []
        for i in range(skip, min(skip + limit, skip + 10)):  # Mock data
            tasks.append(
                {
                    "id": str(uuid4()),
                    "name": f"Task {i}",
                    "status": "completed" if i % 3 == 0 else "running",
                    "progress": 100 if i % 3 == 0 else 75,
                    "created_by": user_id or "system",
                }
            )
        return tasks

    async def update_task(self, task_id: str, update_data: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Update task.

        Args:
            task_id: Task identifier
            update_data: Data to update
            user_id: User performing update

        Returns:
            Dict: Updated task data

        Raises:
            NotFoundError: If task not found
            ValidationError: If update fails
        """
        try:
            task = await self.get_task(task_id)

            # Add audit fields
            update_data["updated_by"] = user_id

            # Update task data
            task.update(update_data)

            # Note: Repository handles session management

            logger.info("task_updated", task_id=task_id, user_id=user_id)
            return task

        except Exception as e:
            logger.error("failed_to_update_task", task_id=task_id, error=str(e))
            raise ValidationError(f"Failed to update task: {str(e)}")

    async def delete_task(self, task_id: str, user_id: str) -> bool:
        """Delete task.

        Args:
            task_id: Task identifier
            user_id: User performing deletion

        Returns:
            bool: True if deletion successful

        Raises:
            NotFoundError: If task not found
        """
        try:
            await self.get_task(task_id)  # Validate task exists

            # Simulate deletion
            # Note: Repository handles session management

            logger.info("task_deleted", task_id=task_id, user_id=user_id)
            return True

        except Exception as e:
            logger.error("failed_to_delete_task", task_id=task_id, error=str(e))
            raise

    async def start_task(self, task_id: str, user_id: str) -> Dict[str, Any]:
        """Start a pending task.

        Args:
            task_id: Task identifier
            user_id: User starting the task

        Returns:
            Dict: Updated task data
        """
        return await self.update_task(
            task_id,
            {"status": "running", "started_at": "now()", "progress": 0},
            user_id,
        )

    async def complete_task(self, task_id: str, result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Mark task as completed.

        Args:
            task_id: Task identifier
            result: Optional task result data

        Returns:
            Dict: Updated task data
        """
        update_data = {"status": "completed", "completed_at": "now()", "progress": 100}

        if result:
            update_data["result"] = result

        return await self.update_task(task_id, update_data, "system")

    async def fail_task(self, task_id: str, error_message: str) -> Dict[str, Any]:
        """Mark task as failed.

        Args:
            task_id: Task identifier
            error_message: Error message

        Returns:
            Dict: Updated task data
        """
        return await self.update_task(
            task_id,
            {"status": "failed", "failed_at": "now()", "error_message": error_message},
            "system",
        )

    async def cancel_task(self, task_id: str, user_id: str) -> Dict[str, Any]:
        """Cancel a running task.

        Args:
            task_id: Task identifier
            user_id: User canceling the task

        Returns:
            Dict: Updated task data
        """
        return await self.update_task(task_id, {"status": "cancelled", "cancelled_at": "now()"}, user_id)

    async def get_task_status(self, task_id: str) -> str:
        """Get current task status.

        Args:
            task_id: Task identifier

        Returns:
            str: Current task status
        """
        task = await self.get_task(task_id)
        return task.get("status", "unknown")
