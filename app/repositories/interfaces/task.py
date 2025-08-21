"""Task repository interface."""

import uuid
from abc import abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from app.models.task import Task

from .base import IBaseRepository


class ITaskRepository(IBaseRepository[Task]):
    """Interface for task repository operations."""

    @abstractmethod
    async def get_by_status(
        self, status: str, organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 100
    ) -> List[Task]:
        """
        Get tasks by status.

        Args:
            status: Task status
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of tasks with specified status
        """
        raise NotImplementedError

    @abstractmethod
    async def get_pending_tasks(
        self, organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 100
    ) -> List[Task]:
        """
        Get all pending tasks.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of pending tasks
        """
        raise NotImplementedError

    @abstractmethod
    async def get_running_tasks(
        self, organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 100
    ) -> List[Task]:
        """
        Get all running tasks.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of running tasks
        """
        raise NotImplementedError

    @abstractmethod
    async def get_tasks_by_user(
        self, user_id: Union[str, uuid.UUID], organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 50
    ) -> List[Task]:
        """
        Get tasks created by a specific user.

        Args:
            user_id: User ID
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of tasks created by the user
        """
        raise NotImplementedError

    @abstractmethod
    async def get_tasks_by_type(
        self, task_type: str, organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 100
    ) -> List[Task]:
        """
        Get tasks by type.

        Args:
            task_type: Task type
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of tasks of specified type
        """
        raise NotImplementedError

    @abstractmethod
    async def update_task_status(
        self,
        task_id: Union[str, uuid.UUID],
        status: str,
        progress: Optional[int] = None,
        result: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Update task status and related information.

        Args:
            task_id: Task ID
            status: New status
            progress: Optional progress percentage
            result: Optional task result
            error_message: Optional error message
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if update successful, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def start_task(
        self, task_id: Union[str, uuid.UUID], organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> bool:
        """
        Mark task as started.

        Args:
            task_id: Task ID
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if task started successfully, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def complete_task(
        self,
        task_id: Union[str, uuid.UUID],
        result: Optional[Dict[str, Any]] = None,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Mark task as completed.

        Args:
            task_id: Task ID
            result: Optional task result
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if task completed successfully, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def fail_task(
        self,
        task_id: Union[str, uuid.UUID],
        error_message: str,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Mark task as failed.

        Args:
            task_id: Task ID
            error_message: Error message
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if task marked as failed successfully, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def cancel_task(
        self,
        task_id: Union[str, uuid.UUID],
        cancelled_by: str = "system",
        organization_id: Optional[Union[str, uuid.UUID]] = None,
    ) -> bool:
        """
        Cancel a task.

        Args:
            task_id: Task ID
            cancelled_by: User who cancelled the task
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            True if task cancelled successfully, False otherwise
        """
        raise NotImplementedError

    @abstractmethod
    async def get_task_statistics(
        self,
        organization_id: Optional[Union[str, uuid.UUID]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get task statistics.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering
            start_date: Optional start date filter
            end_date: Optional end date filter

        Returns:
            Dictionary containing task statistics
        """
        raise NotImplementedError

    @abstractmethod
    async def get_overdue_tasks(
        self, organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 100
    ) -> List[Task]:
        """
        Get overdue tasks.

        Args:
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of overdue tasks
        """
        raise NotImplementedError

    @abstractmethod
    async def search_tasks(
        self, query: str, organization_id: Optional[Union[str, uuid.UUID]] = None, limit: int = 20
    ) -> List[Task]:
        """
        Search tasks by name, description, or type.

        Args:
            query: Search query
            organization_id: Optional organization ID for multi-tenant filtering
            limit: Maximum number of results

        Returns:
            List of matching tasks
        """
        raise NotImplementedError

    @abstractmethod
    async def cleanup_completed_tasks(
        self, retention_days: int, organization_id: Optional[Union[str, uuid.UUID]] = None
    ) -> int:
        """
        Clean up completed tasks based on retention policy.

        Args:
            retention_days: Number of days to retain completed tasks
            organization_id: Optional organization ID for multi-tenant filtering

        Returns:
            Number of tasks cleaned up
        """
        raise NotImplementedError
