"""Celery configuration for async task processing."""

import os
from typing import Any, Dict

from celery import Celery
from kombu import Queue

from app.core.config import settings

# Create Celery instance
celery_app = Celery("violentutf-api")

# Configuration
celery_config: Dict[str, Any] = {
    # Broker settings
    "broker_url": os.getenv("CELERY_BROKER_URL", "redis://redis:6379/1"),
    "result_backend": os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/2"),
    # Task settings
    "task_serializer": "json",
    "result_serializer": "json",
    "accept_content": ["json"],
    "result_expires": 3600,  # 1 hour
    "task_always_eager": False,
    "task_eager_propagates": True,
    "worker_prefetch_multiplier": 1,
    "task_acks_late": True,
    "worker_hijack_root_logger": False,
    # Queue configuration
    "task_default_queue": "default",
    "task_routes": {
        "app.celery.tasks.execute_scan_task": {"queue": "scans"},
        "app.celery.tasks.execute_task": {"queue": "tasks"},
        "app.celery.tasks.generate_report_task": {"queue": "reports"},
    },
    "task_queues": [
        Queue("default", routing_key="default"),
        Queue("scans", routing_key="scans"),
        Queue("tasks", routing_key="tasks"),
        Queue("reports", routing_key="reports"),
    ],
    # Worker settings
    "worker_max_tasks_per_child": 1000,
    "worker_disable_rate_limits": False,
    # Monitoring
    "worker_send_task_events": True,
    "task_send_sent_event": True,
    # Security
    "worker_pool_restarts": True,
    # Timezone
    "timezone": "UTC",
    "enable_utc": True,
    # Retry policy
    "task_default_retry_delay": 60,  # 1 minute
    "task_max_retries": 3,
}

# Apply configuration
celery_app.config_from_object(celery_config)

# Auto-discover tasks
celery_app.autodiscover_tasks(
    [
        "app.celery.tasks",
    ]
)

# Import tasks to register them
from app.celery import tasks  # noqa: E402

# Configure logging
if not os.getenv("CELERY_WORKER_HIJACK_ROOT_LOGGER", "False").lower() == "true":
    import logging

    logging.getLogger("celery").setLevel(logging.INFO)


# Health check task
@celery_app.task(bind=True)
def celery_health_check(self: Any) -> Dict[str, Any]:
    """Health check task for Celery workers."""
    return {
        "status": "healthy",
        "worker_id": self.request.id,
        "timestamp": self.request.utc,
    }


def get_celery_app() -> Celery:
    """Get the Celery application instance."""
    return celery_app
