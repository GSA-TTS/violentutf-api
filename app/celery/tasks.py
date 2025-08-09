"""Celery tasks for async processing."""

import asyncio
import traceback
from datetime import datetime
from typing import Any, Dict, Optional

from celery import Task as CeleryTask
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.celery.celery import celery_app
from app.db.session import get_db
from app.models.report import Report, ReportStatus
from app.models.scan import Scan, ScanStatus
from app.models.task import Task as TaskModel
from app.models.task import TaskResult, TaskStatus

logger = get_logger(__name__)


class AsyncTask(CeleryTask):
    """Base class for async tasks with database session support."""

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Execute task with async support."""
        return asyncio.run(self.run_async(*args, **kwargs))

    async def run_async(self, *args: Any, **kwargs: Any) -> Any:
        """Override this method in subclasses."""
        raise NotImplementedError("Subclasses must implement run_async")


@celery_app.task(bind=True, base=AsyncTask)
async def execute_task(
    self: AsyncTask, task_id: str, config_override: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Execute a generic task asynchronously.

    Args:
        task_id: ID of the task to execute
        config_override: Optional configuration overrides
    """
    logger.info(f"Starting task execution: {task_id}")

    async with get_db() as db:
        try:
            # Get task from database
            task = await db.get(TaskModel, task_id)
            if not task:
                logger.error(f"Task not found: {task_id}")
                return {"status": "error", "message": "Task not found"}

            # Update task status
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.utcnow()
            task.celery_task_id = self.request.id
            await db.commit()

            # Apply config overrides
            config = task.config.copy()
            if config_override:
                config.update(config_override)

            # Execute task based on type
            result_data = await _execute_task_by_type(task, config)

            # Create task result
            task_result = TaskResult(
                task_id=task_id,
                result_type="output",
                name="Task Execution Result",
                data=result_data,
                result_metadata={
                    "execution_time": (datetime.utcnow() - task.started_at).total_seconds(),
                    "worker_id": self.request.id,
                },
                is_primary=True,
                created_by="system",
            )

            db.add(task_result)

            # Update task as completed
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.utcnow()
            task.output_data = result_data
            task.progress = 100
            task.progress_message = "Task completed successfully"

            await db.commit()

            # Send webhook if configured
            if task.webhook_url:
                await _send_webhook(task)

            logger.info(f"Task completed successfully: {task_id}")
            return {"status": "completed", "result": result_data}

        except Exception as e:
            logger.error(f"Task execution failed: {task_id}, error: {e}")

            # Update task as failed
            if "task" in locals() and task is not None:
                task.status = TaskStatus.FAILED
                task.completed_at = datetime.utcnow()
                task.error_message = str(e)
                task.error_details = {
                    "error_type": type(e).__name__,
                    "traceback": traceback.format_exc(),
                    "worker_id": self.request.id,
                }
                await db.commit()

            raise


@celery_app.task(bind=True, base=AsyncTask)
async def execute_scan_task(
    self: AsyncTask, scan_id: str, task_id: str, config_override: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Execute a security scan asynchronously.

    Args:
        scan_id: ID of the scan to execute
        task_id: ID of the associated task
        config_override: Optional configuration overrides
    """
    logger.info(f"Starting scan execution: {scan_id}")

    async with get_db() as db:
        try:
            # Get scan and task from database
            scan = await db.get(Scan, scan_id)
            task = await db.get(TaskModel, task_id)

            if not scan or not task:
                logger.error(f"Scan or task not found: scan={scan_id}, task={task_id}")
                return {"status": "error", "message": "Scan or task not found"}

            # Update scan and task status
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            scan.progress = 10
            scan.current_phase = "Initialization"

            task.status = TaskStatus.RUNNING
            task.started_at = datetime.utcnow()
            task.celery_task_id = self.request.id
            task.progress = 10
            task.progress_message = "Initializing scan..."

            await db.commit()

            # Apply config overrides
            config = scan.scan_config.copy()
            if config_override:
                config.update(config_override)

            # Execute scan based on type
            scan_results = await _execute_scan_by_type(scan, config, db)

            # Update scan as completed
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.progress = 100
            scan.current_phase = "Completed"

            # Update task as completed
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.utcnow()
            task.progress = 100
            task.progress_message = "Scan completed successfully"
            task.output_data = scan_results

            await db.commit()

            # Send webhook if configured
            if task.webhook_url:
                await _send_webhook(task)

            logger.info(f"Scan completed successfully: {scan_id}")
            return {"status": "completed", "result": scan_results}

        except Exception as e:
            logger.error(f"Scan execution failed: {scan_id}, error: {e}")

            # Update scan and task as failed
            if "scan" in locals() and scan is not None:
                scan.status = ScanStatus.FAILED
                scan.completed_at = datetime.utcnow()
                scan.error_message = str(e)
                scan.error_details = {"error_type": type(e).__name__, "traceback": traceback.format_exc()}

            if "task" in locals() and task is not None:
                task.status = TaskStatus.FAILED
                task.completed_at = datetime.utcnow()
                task.error_message = str(e)
                task.error_details = {"error_type": type(e).__name__, "traceback": traceback.format_exc()}

            await db.commit()
            raise


@celery_app.task(bind=True, base=AsyncTask)
async def generate_report_task(self: AsyncTask, report_id: str) -> Dict[str, Any]:
    """
    Generate a report asynchronously.

    Args:
        report_id: ID of the report to generate
    """
    logger.info(f"Starting report generation: {report_id}")

    async with get_db() as db:
        try:
            # Get report from database
            report = await db.get(Report, report_id)
            if not report:
                logger.error(f"Report not found: {report_id}")
                return {"status": "error", "message": "Report not found"}

            # Update report status
            report.status = ReportStatus.GENERATING
            await db.commit()

            # Generate report content based on type
            report_content = await _generate_report_content(report, db)

            # Update report with generated content
            report.content = report_content
            report.status = ReportStatus.COMPLETED
            report.generated_at = datetime.utcnow()

            await db.commit()

            logger.info(f"Report generated successfully: {report_id}")
            return {"status": "completed", "report_id": report_id}

        except Exception as e:
            logger.error(f"Report generation failed: {report_id}, error: {e}")

            # Update report as failed
            if "report" in locals() and report is not None:
                report.status = ReportStatus.FAILED
                report.error_message = str(e)
                report.error_details = {"error_type": type(e).__name__, "traceback": traceback.format_exc()}
                await db.commit()

            raise


async def _execute_task_by_type(task: TaskModel, config: Dict[str, Any]) -> Dict[str, Any]:
    """Execute task based on its type."""
    # This is a placeholder implementation
    # In a real implementation, you would dispatch to different handlers based on task.task_type
    await asyncio.sleep(1)  # Simulate work

    return {
        "task_id": task.id,
        "task_type": task.task_type,
        "processed": True,
        "config_used": config,
        "simulated_results": ["result1", "result2", "result3"],
    }


async def _execute_scan_by_type(scan: Scan, config: Dict[str, Any], db: AsyncSession) -> Dict[str, Any]:
    """Execute scan based on its type."""
    # This is a placeholder implementation
    # In a real implementation, you would integrate with PyRIT, Garak, etc.

    # Simulate scan progress updates
    for progress in [25, 50, 75, 90]:
        scan.progress = progress
        scan.current_phase = f"Processing... {progress}%"
        await db.commit()
        await asyncio.sleep(0.5)  # Simulate work

    # Simulate findings
    findings_data = {
        "total_tests": 100,
        "passed_tests": 85,
        "failed_tests": 15,
        "findings": [
            {"severity": "high", "title": "Potential SQL Injection", "confidence": 0.8},
            {"severity": "medium", "title": "Weak Password Policy", "confidence": 0.9},
            {"severity": "low", "title": "Missing Security Headers", "confidence": 0.7},
        ],
    }

    # Update scan metrics
    scan.total_tests = int(findings_data["total_tests"])
    scan.completed_tests = int(findings_data["passed_tests"])
    scan.failed_tests = int(findings_data["failed_tests"])
    findings_list = findings_data["findings"]
    if isinstance(findings_list, list):
        scan.findings_count = len(findings_list)
        scan.high_findings = len([f for f in findings_list if f.get("severity") == "high"])
        scan.medium_findings = len([f for f in findings_list if f.get("severity") == "medium"])
        scan.low_findings = len([f for f in findings_list if f.get("severity") == "low"])
    else:
        scan.findings_count = 0
        scan.high_findings = 0
        scan.medium_findings = 0
        scan.low_findings = 0

    return findings_data


async def _generate_report_content(report: Report, db: AsyncSession) -> Dict[str, Any]:
    """Generate report content based on report type."""
    # This is a placeholder implementation
    # In a real implementation, you would generate different report formats

    return {
        "report_id": report.id,
        "report_type": report.report_type,
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {"total_items": 10, "processed": 10, "success_rate": 1.0},
        "details": {"sections": ["Executive Summary", "Technical Details", "Recommendations"], "format": report.format},
    }


async def _send_webhook(task: TaskModel) -> None:
    """Send webhook notification for task completion."""
    # This is a placeholder implementation
    # In a real implementation, you would send HTTP POST to task.webhook_url
    logger.info(f"Webhook would be sent to: {task.webhook_url} for task: {task.id}")

    # Update webhook_called flag
    task.webhook_called = True
