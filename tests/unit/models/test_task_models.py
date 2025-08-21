"""Unit tests for Task models."""

import datetime
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.models.task import Task, TaskPriority, TaskResult, TaskStatus


class TestTaskModel:
    """Test cases for Task model."""

    def test_task_creation(self):
        """Test basic task creation."""
        task = Task(
            name="Test Task",
            task_type="test_type",
            description="A test task",
            priority=TaskPriority.NORMAL,
            input_data={"key": "value"},
            config={"timeout": 300},
            created_by="testuser",
        )

        assert task.name == "Test Task"
        assert task.task_type == "test_type"
        assert task.status == TaskStatus.PENDING  # Default
        assert task.priority == TaskPriority.NORMAL
        assert task.progress == 0  # Default
        assert task.retry_count == 0  # Default
        assert task.max_retries == 3  # Default
        assert task.webhook_called is False  # Default
        assert task.input_data == {"key": "value"}
        assert task.config == {"timeout": 300}

    def test_task_status_enum_values(self):
        """Test TaskStatus enum values."""
        assert TaskStatus.PENDING == "pending"
        assert TaskStatus.RUNNING == "running"
        assert TaskStatus.COMPLETED == "completed"
        assert TaskStatus.FAILED == "failed"
        assert TaskStatus.CANCELLED == "cancelled"
        assert TaskStatus.TIMEOUT == "timeout"

    def test_task_priority_enum_values(self):
        """Test TaskPriority enum values."""
        assert TaskPriority.LOW == "low"
        assert TaskPriority.NORMAL == "normal"
        assert TaskPriority.HIGH == "high"
        assert TaskPriority.URGENT == "urgent"

    def test_task_repr(self):
        """Test task string representation."""
        task = Task(name="Test Task", task_type="test_type", created_by="testuser")
        task.id = "test-id-123"
        task.status = TaskStatus.RUNNING

        repr_str = repr(task)
        assert "Test Task" in repr_str
        assert "test_type" in repr_str
        assert "RUNNING" in repr_str
        assert "test-id-123" in repr_str

    def test_task_default_values(self):
        """Test task default values."""
        task = Task(name="Minimal Task", task_type="minimal", created_by="testuser")

        assert task.status == TaskStatus.PENDING
        assert task.priority == TaskPriority.NORMAL
        assert task.progress == 0
        assert task.retry_count == 0
        assert task.max_retries == 3
        assert task.webhook_called is False
        assert task.input_data == {}
        assert task.config == {}
        assert task.output_data is None
        assert task.error_message is None
        assert task.error_details is None

    def test_task_json_fields(self):
        """Test task JSON fields."""
        complex_data = {"nested": {"key": "value"}, "list": [1, 2, 3], "boolean": True}

        task = Task(
            name="Complex Task",
            task_type="complex",
            input_data=complex_data,
            output_data=complex_data,
            config={"setting1": True, "setting2": [1, 2]},
            error_details={"error_code": 500, "details": ["error1", "error2"]},
            created_by="testuser",
        )

        assert task.input_data == complex_data
        assert task.output_data == complex_data
        assert task.config["setting1"] is True
        assert task.config["setting2"] == [1, 2]
        assert task.error_details["error_code"] == 500
        assert task.error_details["details"] == ["error1", "error2"]

    def test_task_webhook_fields(self):
        """Test task webhook-related fields."""
        task = Task(
            name="Webhook Task",
            task_type="webhook_test",
            webhook_url="https://example.com/webhook",
            webhook_secret="secret123",
            webhook_called=True,
            created_by="testuser",
        )

        assert task.webhook_url == "https://example.com/webhook"
        assert task.webhook_secret == "secret123"
        assert task.webhook_called is True


class TestTaskResultModel:
    """Test cases for TaskResult model."""

    def test_task_result_creation(self):
        """Test basic task result creation."""
        task_id = str(uuid4())
        result = TaskResult(
            task_id=task_id,
            result_type="output",
            name="Test Result",
            data={"key": "value"},
            result_metadata={"generated_at": datetime.now(timezone.utc).isoformat()},
            is_primary=True,
            created_by="testuser",
        )

        assert result.task_id == task_id
        assert result.result_type == "output"
        assert result.name == "Test Result"
        assert result.data == {"key": "value"}
        assert "generated_at" in result.result_metadata
        assert result.is_primary is True

    def test_task_result_default_values(self):
        """Test task result default values."""
        task_id = str(uuid4())
        result = TaskResult(task_id=task_id, result_type="log", name="Test Log", created_by="testuser")

        assert result.data == {}
        assert result.result_metadata == {}
        assert result.is_primary is False
        assert result.file_path is None
        assert result.file_size is None
        assert result.file_hash is None

    def test_task_result_file_fields(self):
        """Test task result file-related fields."""
        task_id = str(uuid4())
        result = TaskResult(
            task_id=task_id,
            result_type="file",
            data={"filename": "output.json"},
            file_path="/tmp/output.json",  # nosec B108 - test data
            file_size=1024,
            file_hash="sha256:abc123def456",
            created_by="testuser",
        )

        assert result.file_path == "/tmp/output.json"  # nosec B108 - test assertion
        assert result.file_size == 1024
        assert result.file_hash == "sha256:abc123def456"
        assert result.data["filename"] == "output.json"

    def test_task_result_complex_data(self):
        """Test task result with complex data structures."""
        task_id = str(uuid4())
        complex_result = {
            "statistics": {
                "total_processed": 1000,
                "success_rate": 0.95,
                "errors": [{"type": "timeout", "count": 30}, {"type": "validation", "count": 20}],
            },
            "summary": {
                "start_time": "2025-01-01T00:00:00Z",
                "end_time": "2025-01-01T01:00:00Z",
                "duration_seconds": 3600,
            },
        }

        complex_metadata = {
            "version": "1.0",
            "processor": "task_engine_v2",
            "environment": "test",
            "tags": ["automated", "batch_process"],
        }

        result = TaskResult(
            task_id=task_id,
            result_type="statistics",
            data=complex_result,
            result_metadata=complex_metadata,
            created_by="testuser",
        )

        assert result.data["statistics"]["total_processed"] == 1000
        assert result.data["statistics"]["success_rate"] == 0.95
        assert len(result.data["statistics"]["errors"]) == 2
        assert result.result_metadata["version"] == "1.0"
        assert result.result_metadata["tags"] == ["automated", "batch_process"]

    def test_task_result_repr(self):
        """Test task result string representation."""
        task_id = str(uuid4())
        result = TaskResult(task_id=task_id, result_type="output", created_by="testuser")
        result.id = "result-id-123"

        repr_str = repr(result)
        assert "result-id-123" in repr_str
        assert task_id in repr_str
        assert "output" in repr_str

    def test_task_result_primary_flag(self):
        """Test task result primary flag behavior."""
        task_id = str(uuid4())

        # Primary result
        primary_result = TaskResult(task_id=task_id, result_type="final_output", is_primary=True, created_by="testuser")

        # Secondary result
        secondary_result = TaskResult(
            task_id=task_id, result_type="intermediate_log", is_primary=False, created_by="testuser"
        )

        assert primary_result.is_primary is True
        assert secondary_result.is_primary is False

    def test_task_result_types(self):
        """Test different task result types."""
        task_id = str(uuid4())

        result_types = ["output", "log", "error", "metrics", "file", "screenshot", "report"]

        for result_type in result_types:
            result = TaskResult(
                task_id=task_id,
                result_type=result_type,
                data={f"{result_type}_data": True},
                created_by="testuser",
            )
            assert result.result_type == result_type
            assert result.data[f"{result_type}_data"] is True
