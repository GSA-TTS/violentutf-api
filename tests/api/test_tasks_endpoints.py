"""Tests for task management API endpoints."""

from datetime import datetime
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.task import Task, TaskPriority, TaskResult, TaskStatus
from app.schemas.task import TaskCreate, TaskStatusUpdate, TaskUpdate
from tests.helpers.database import create_test_task, create_test_user


class TestTasksEndpoints:
    """Test cases for task management endpoints."""

    async def test_create_task_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful task creation."""
        task_data = {
            "name": "Test Task",
            "task_type": "test_type",
            "description": "A test task",
            "priority": "NORMAL",
            "input_data": {"key": "value"},
            "config": {"timeout": 300},
            "webhook_url": "https://example.com/webhook",
        }

        response = await async_client.post(
            "/api/v1/tasks/", json=task_data, headers={"Authorization": f"Bearer {auth_token}"}
        )

        print(f"Response status: {response.status_code}")
        print(f"Response text: {response.text}")

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["name"] == task_data["name"]
        assert data["task_type"] == task_data["task_type"]
        assert data["status"] == "PENDING"
        assert data["progress"] == 0
        assert data["webhook_url"] == task_data["webhook_url"]

    async def test_create_task_validation_error(self, async_client, test_user, auth_token):
        """Test task creation with invalid data."""
        task_data = {"name": "", "task_type": "test_type"}  # Invalid: empty name

        response = await async_client.post(
            "/api/v1/tasks/", json=task_data, headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_get_task_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful task retrieval."""
        task = await create_test_task(db_session, created_by=test_user.username)

        response = await async_client.get(f"/api/v1/tasks/{task.id}", headers={"Authorization": f"Bearer {auth_token}"})

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["id"] == task.id
        assert data["name"] == task.name
        assert data["status"] == task.status.value

    async def test_get_task_not_found(self, async_client, test_user, auth_token):
        """Test task retrieval with non-existent ID."""
        fake_id = str(uuid4())

        response = await async_client.get(f"/api/v1/tasks/{fake_id}", headers={"Authorization": f"Bearer {auth_token}"})

        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_list_tasks_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful task listing with pagination."""
        # Create test tasks
        tasks = []
        for i in range(5):
            task = await create_test_task(db_session, name=f"Task {i}", created_by=test_user.username)
            tasks.append(task)

        response = await async_client.get("/api/v1/tasks/?limit=3", headers={"Authorization": f"Bearer {auth_token}"})

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["tasks"]) <= 3
        assert data["total"] >= 5
        assert data["page"] == 1
        assert data["per_page"] == 3
        assert "has_next" in data

    async def test_list_tasks_filtering(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test task listing with filters."""
        # Create tasks with different statuses
        pending_task = await create_test_task(db_session, name="Pending Task", created_by=test_user.username)
        running_task = await create_test_task(
            db_session, name="Running Task", status=TaskStatus.RUNNING, created_by=test_user.username
        )

        response = await async_client.get(
            "/api/v1/tasks/?status=RUNNING", headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["tasks"]) >= 1
        assert all(task["status"] == "RUNNING" for task in data["tasks"])

    async def test_update_task_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful task update."""
        task = await create_test_task(db_session, created_by=test_user.username)

        update_data = {"name": "Updated Task Name", "description": "Updated description", "priority": "HIGH"}

        response = await async_client.put(
            f"/api/v1/tasks/{task.id}", json=update_data, headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["name"] == update_data["name"]
        assert data["description"] == update_data["description"]
        assert data["priority"] == update_data["priority"]

    async def test_update_task_running_fails(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test that updating a running task fails."""
        task = await create_test_task(db_session, status=TaskStatus.RUNNING, created_by=test_user.username)

        update_data = {"name": "Should not update"}

        response = await async_client.put(
            f"/api/v1/tasks/{task.id}", json=update_data, headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    async def test_delete_task_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful task deletion (soft delete)."""
        task = await create_test_task(db_session, created_by=test_user.username)

        response = await async_client.delete(
            f"/api/v1/tasks/{task.id}", headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "Task deleted successfully"

        # Verify task is soft deleted
        response = await async_client.get(f"/api/v1/tasks/{task.id}", headers={"Authorization": f"Bearer {auth_token}"})
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_delete_running_task_fails(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test that deleting a running task fails."""
        task = await create_test_task(db_session, status=TaskStatus.RUNNING, created_by=test_user.username)

        response = await async_client.delete(
            f"/api/v1/tasks/{task.id}", headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    async def test_execute_task_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful task execution."""
        task = await create_test_task(db_session, created_by=test_user.username)

        execution_data = {"priority": "HIGH", "config_override": {"timeout": 600}}

        response = await async_client.post(
            f"/api/v1/tasks/{task.id}/execute",
            json=execution_data,
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_202_ACCEPTED
        data = response.json()
        assert data["task_id"] == task.id
        assert data["execution_id"] == task.id
        assert data["status"] in ["RUNNING", "PENDING"]
        assert "status_url" in data

    async def test_execute_already_running_task_fails(
        self, async_client, test_user, auth_token, db_session: AsyncSession
    ):
        """Test that executing an already running task fails."""
        task = await create_test_task(db_session, status=TaskStatus.RUNNING, created_by=test_user.username)

        response = await async_client.post(
            f"/api/v1/tasks/{task.id}/execute", headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    async def test_cancel_task_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful task cancellation."""
        task = await create_test_task(db_session, status=TaskStatus.RUNNING, created_by=test_user.username)

        response = await async_client.post(
            f"/api/v1/tasks/{task.id}/cancel", headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "Task cancelled successfully"

    async def test_cancel_completed_task_fails(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test that cancelling a completed task fails."""
        task = await create_test_task(db_session, status=TaskStatus.COMPLETED, created_by=test_user.username)

        response = await async_client.post(
            f"/api/v1/tasks/{task.id}/cancel", headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    async def test_update_task_status_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful task status update."""
        task = await create_test_task(db_session, created_by=test_user.username)

        status_data = {
            "status": "RUNNING",
            "progress": 50,
            "progress_message": "Processing...",
            "output_data": {"processed": 100},
        }

        response = await async_client.patch(
            f"/api/v1/tasks/{task.id}/status", json=status_data, headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "Task status updated successfully"

    async def test_retry_task_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful task retry."""
        task = await create_test_task(db_session, status=TaskStatus.FAILED, created_by=test_user.username)

        retry_data = {"reset_progress": True, "clear_errors": True}

        response = await async_client.post(
            f"/api/v1/tasks/{task.id}/retry", json=retry_data, headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == status.HTTP_202_ACCEPTED
        data = response.json()
        assert data["task_id"] == task.id
        assert data["status"] in ["PENDING", "RUNNING"]

    async def test_bulk_delete_tasks_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful bulk task deletion."""
        tasks = []
        for i in range(3):
            task = await create_test_task(db_session, name=f"Task {i}", created_by=test_user.username)
            tasks.append(task)

        task_ids = [task.id for task in tasks]
        bulk_data = {"action": "delete", "task_ids": task_ids}

        response = await async_client.post(
            "/api/v1/tasks/bulk", json=bulk_data, headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total_requested"] == 3
        assert data["successful"] == 3
        assert data["failed"] == 0

    async def test_get_task_stats_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful task statistics retrieval."""
        # Create tasks with different statuses
        await create_test_task(db_session, status=TaskStatus.PENDING, created_by=test_user.username)
        await create_test_task(db_session, status=TaskStatus.RUNNING, created_by=test_user.username)
        await create_test_task(db_session, status=TaskStatus.COMPLETED, created_by=test_user.username)

        response = await async_client.get("/api/v1/tasks/stats", headers={"Authorization": f"Bearer {auth_token}"})

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "total_tasks" in data
        assert "pending_tasks" in data
        assert "running_tasks" in data
        assert "completed_tasks" in data
        assert "failed_tasks" in data
        assert data["total_tasks"] >= 3

    async def test_unauthorized_access(self, async_client):
        """Test that endpoints require authentication."""
        response = await async_client.get("/api/v1/tasks/")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_invalid_task_id_format(self, async_client, test_user, auth_token):
        """Test endpoints with invalid task ID format."""
        response = await async_client.get("/api/v1/tasks/invalid-id", headers={"Authorization": f"Bearer {auth_token}"})
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
class TestTaskResultsEndpoints:
    """Test cases for task results endpoints."""

    async def test_get_task_results_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful task results retrieval."""
        task = await create_test_task(db_session, created_by=test_user.username)

        # Create a task result
        result = TaskResult(
            task_id=task.id,
            result_type="output",
            result_data={"key": "value"},
            result_metadata={"generated_at": datetime.utcnow().isoformat()},
            is_primary=True,
            created_by=test_user.username,
        )
        db_session.add(result)
        await db_session.commit()

        response = await async_client.get(
            f"/api/v1/tasks/{task.id}/results", headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["results"]) == 1
        assert data["results"][0]["task_id"] == task.id
        assert data["results"][0]["result_type"] == "output"
        assert data["results"][0]["is_primary"] is True

    async def test_get_task_results_empty(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test task results retrieval for task with no results."""
        task = await create_test_task(db_session, created_by=test_user.username)

        response = await async_client.get(
            f"/api/v1/tasks/{task.id}/results", headers={"Authorization": f"Bearer {auth_token}"}
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["results"]) == 0
        assert data["total"] == 0
