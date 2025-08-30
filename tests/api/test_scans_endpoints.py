"""Tests for scan management API endpoints."""

from datetime import datetime
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import (
    Scan,
    ScanFinding,
    ScanReport,
    ScanSeverity,
    ScanStatus,
    ScanType,
)
from app.schemas.scan import ScanCreate, ScanUpdate
from tests.helpers.database import create_test_scan, create_test_user


class TestScansEndpoints:
    """Test cases for scan management endpoints."""

    async def test_create_scan_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful scan creation and immediate execution."""
        scan_data = {
            "name": "Test Security Scan",
            "scan_type": "PYRIT_ORCHESTRATOR",
            "description": "A test security scan",
            "target_config": {
                "endpoint": "https://api.example.com",
                "auth_type": "bearer",
            },
            "scan_config": {"max_requests": 100, "timeout": 30},
            "parameters": {"intensity": "medium"},
            "tags": ["security", "test"],
            "webhook_url": "https://example.com/webhook",
            "webhook_secret": "secret123",
        }

        response = await async_client.post(
            "/api/v1/scans/",
            json=scan_data,
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_202_ACCEPTED
        data = response.json()
        assert data["scan_id"] is not None
        assert data["execution_id"] is not None
        assert data["task_id"] is not None
        assert data["status"] in ["INITIALIZING", "PENDING"]
        assert data["webhook_configured"] is True
        assert "status_url" in data

    async def test_create_scan_without_execution(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test scan creation without immediate execution."""
        scan_data = {
            "name": "Test Scan No Execute",
            "scan_type": "GARAK_PROBE",
            "description": "A test scan without execution",
            "target_config": {"endpoint": "https://api.example.com"},
            "scan_config": {"max_requests": 50},
        }

        response = await async_client.post(
            "/api/v1/scans/?execute_immediately=false",
            json=scan_data,
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_202_ACCEPTED
        data = response.json()
        assert data["scan_id"] is not None
        assert data["task_id"] is None  # No task created since not executing
        assert data["status"] == "PENDING"
        assert data["webhook_configured"] is False

    async def test_create_scan_validation_error(self, async_client, test_user, auth_token):
        """Test scan creation with invalid data."""
        scan_data = {
            "name": "",  # Invalid: empty name
            "scan_type": "INVALID_TYPE",  # Invalid scan type
            "target_config": {},
        }

        response = await async_client.post(
            "/api/v1/scans/",
            json=scan_data,
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_get_scan_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful scan retrieval (ADR-007 status polling)."""
        scan = await create_test_scan(db_session, created_by=test_user.username)

        response = await async_client.get(
            f"/api/v1/scans/{scan.id}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["id"] == scan.id
        assert data["name"] == scan.name
        assert data["scan_type"] == scan.scan_type.value
        assert data["status"] == scan.status.value

    async def test_get_scan_not_found(self, async_client, test_user, auth_token):
        """Test scan retrieval with non-existent ID."""
        fake_id = str(uuid4())

        response = await async_client.get(
            f"/api/v1/scans/{fake_id}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_list_scans_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful scan listing with pagination."""
        # Create test scans
        scans = []
        for i in range(5):
            scan = await create_test_scan(
                db_session,
                name=f"Security Scan {i}",
                scan_type=(ScanType.PYRIT_ORCHESTRATOR if i % 2 == 0 else ScanType.GARAK_PROBE),
                created_by=test_user.username,
            )
            scans.append(scan)

        response = await async_client.get("/api/v1/scans/?limit=3", headers={"Authorization": f"Bearer {auth_token}"})

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["scans"]) <= 3
        assert data["total"] >= 5
        assert data["page"] == 1
        assert data["per_page"] == 3
        assert "has_next" in data

    async def test_list_scans_filtering(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test scan listing with filters."""
        # Create scans with different types and statuses
        pyrit_scan = await create_test_scan(
            db_session,
            name="PyRIT Scan",
            scan_type=ScanType.PYRIT_ORCHESTRATOR,
            status=ScanStatus.RUNNING,
            created_by=test_user.username,
        )
        garak_scan = await create_test_scan(
            db_session,
            name="Garak Scan",
            scan_type=ScanType.GARAK_PROBE,
            status=ScanStatus.COMPLETED,
            created_by=test_user.username,
        )

        # Filter by scan type
        response = await async_client.get(
            "/api/v1/scans/?scan_type=PYRIT_ORCHESTRATOR",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["scans"]) >= 1
        assert all(scan["scan_type"] == "PYRIT_ORCHESTRATOR" for scan in data["scans"])

        # Filter by status
        response = await async_client.get(
            "/api/v1/scans/?status=RUNNING",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["scans"]) >= 1
        assert all(scan["status"] == "RUNNING" for scan in data["scans"])

    async def test_update_scan_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful scan update."""
        scan = await create_test_scan(db_session, created_by=test_user.username)

        update_data = {
            "name": "Updated Security Scan",
            "description": "Updated description",
            "parameters": {"intensity": "high"},
        }

        response = await async_client.put(
            f"/api/v1/scans/{scan.id}",
            json=update_data,
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["name"] == update_data["name"]
        assert data["description"] == update_data["description"]
        assert data["parameters"]["intensity"] == "high"

    async def test_update_running_scan_fails(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test that updating a running scan fails."""
        scan = await create_test_scan(db_session, status=ScanStatus.RUNNING, created_by=test_user.username)

        update_data = {"name": "Should not update"}

        response = await async_client.put(
            f"/api/v1/scans/{scan.id}",
            json=update_data,
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert "currently running" in data["detail"]

    async def test_delete_scan_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful scan deletion (soft delete)."""
        scan = await create_test_scan(db_session, created_by=test_user.username)

        response = await async_client.delete(
            f"/api/v1/scans/{scan.id}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "Scan deleted successfully"

        # Verify scan is soft deleted
        response = await async_client.get(
            f"/api/v1/scans/{scan.id}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_delete_running_scan_fails(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test that deleting a running scan fails."""
        scan = await create_test_scan(db_session, status=ScanStatus.RUNNING, created_by=test_user.username)

        response = await async_client.delete(
            f"/api/v1/scans/{scan.id}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert "Cannot delete running scan" in data["detail"]

    async def test_execute_scan_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful scan execution."""
        scan = await create_test_scan(db_session, created_by=test_user.username)

        execution_data = {"config_override": {"timeout": 60, "max_requests": 200}}

        response = await async_client.post(
            f"/api/v1/scans/{scan.id}/execute",
            json=execution_data,
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_202_ACCEPTED
        data = response.json()
        assert data["scan_id"] == scan.id
        assert data["task_id"] is not None
        assert data["status"] in ["INITIALIZING", "RUNNING"]
        assert "status_url" in data

    async def test_execute_already_running_scan_fails(
        self, async_client, test_user, auth_token, db_session: AsyncSession
    ):
        """Test that executing an already running scan fails."""
        scan = await create_test_scan(db_session, status=ScanStatus.RUNNING, created_by=test_user.username)

        response = await async_client.post(
            f"/api/v1/scans/{scan.id}/execute",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert "already running" in data["detail"]

    async def test_cancel_scan_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful scan cancellation."""
        scan = await create_test_scan(db_session, status=ScanStatus.RUNNING, created_by=test_user.username)

        response = await async_client.post(
            f"/api/v1/scans/{scan.id}/cancel",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "Scan cancelled successfully"

    async def test_cancel_completed_scan_fails(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test that cancelling a completed scan fails."""
        scan = await create_test_scan(db_session, status=ScanStatus.COMPLETED, created_by=test_user.username)

        response = await async_client.post(
            f"/api/v1/scans/{scan.id}/cancel",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    async def test_get_scan_findings_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful scan findings retrieval."""
        scan = await create_test_scan(db_session, created_by=test_user.username)

        # Create test findings
        findings = []
        for i in range(3):
            finding = ScanFinding(
                scan_id=scan.id,
                title=f"Security Finding {i}",
                description=f"Description for finding {i}",
                severity=ScanSeverity.HIGH if i == 0 else ScanSeverity.MEDIUM,
                category="injection",
                vulnerability_type="sql_injection",
                confidence_score=0.8,
                evidence={"request": f"SELECT * FROM users WHERE id = {i}"},  # nosec B608 - test data
                created_by=test_user.username,
            )
            findings.append(finding)
            db_session.add(finding)
        await db_session.commit()

        response = await async_client.get(
            f"/api/v1/scans/{scan.id}/findings",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["findings"]) == 3
        assert data["total"] == 3
        assert all(finding["scan_id"] == scan.id for finding in data["findings"])

    async def test_get_scan_findings_filtering(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test scan findings retrieval with filters."""
        scan = await create_test_scan(db_session, created_by=test_user.username)

        # Create findings with different severities
        high_finding = ScanFinding(
            scan_id=scan.id,
            title="Critical SQL Injection",
            description="High severity finding",
            severity=ScanSeverity.HIGH,
            category="injection",
            vulnerability_type="sql_injection",
            confidence_score=0.9,
            created_by=test_user.username,
        )
        medium_finding = ScanFinding(
            scan_id=scan.id,
            title="XSS Vulnerability",
            description="Medium severity finding",
            severity=ScanSeverity.MEDIUM,
            category="xss",
            vulnerability_type="reflected_xss",
            confidence_score=0.7,
            created_by=test_user.username,
        )
        db_session.add_all([high_finding, medium_finding])
        await db_session.commit()

        # Filter by severity
        response = await async_client.get(
            f"/api/v1/scans/{scan.id}/findings?severity=HIGH",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["findings"]) == 1
        assert data["findings"][0]["severity"] == "HIGH"
        assert data["findings"][0]["title"] == "Critical SQL Injection"

    async def test_get_scan_reports_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful scan reports retrieval."""
        scan = await create_test_scan(db_session, created_by=test_user.username)

        # Create test reports
        reports = []
        for i, format_type in enumerate(["json", "pdf", "html"]):
            report = ScanReport(
                scan_id=scan.id,
                name=f"Security Report {i+1}",
                report_type="security_assessment",
                format=format_type,
                content={"summary": f"Report {i+1} content"},
                summary={"findings": i + 1, "severity": "medium"},
                template_name="standard_template",
                generated_at=datetime.utcnow(),
                created_by=test_user.username,
            )
            reports.append(report)
            db_session.add(report)
        await db_session.commit()

        response = await async_client.get(
            f"/api/v1/scans/{scan.id}/reports",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 3
        assert all(report["scan_id"] == scan.id for report in data)
        formats = {report["format"] for report in data}
        assert formats == {"json", "pdf", "html"}

    async def test_get_scan_stats_success(self, async_client, test_user, auth_token, db_session: AsyncSession):
        """Test successful scan statistics retrieval."""
        # Create scans with different statuses
        scans = [
            await create_test_scan(db_session, status=ScanStatus.PENDING, created_by=test_user.username),
            await create_test_scan(db_session, status=ScanStatus.RUNNING, created_by=test_user.username),
            await create_test_scan(
                db_session,
                status=ScanStatus.COMPLETED,
                findings_count=5,
                critical_findings=1,
                high_findings=2,
                created_by=test_user.username,
            ),
            await create_test_scan(db_session, status=ScanStatus.FAILED, created_by=test_user.username),
        ]

        response = await async_client.get("/api/v1/scans/stats", headers={"Authorization": f"Bearer {auth_token}"})

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "total_scans" in data
        assert "pending_scans" in data
        assert "running_scans" in data
        assert "completed_scans" in data
        assert "failed_scans" in data
        assert "total_findings" in data
        assert "critical_findings" in data
        assert "high_findings" in data
        assert "medium_findings" in data
        assert "low_findings" in data
        assert data["total_scans"] >= 4
        assert data["total_findings"] >= 5
        assert data["critical_findings"] >= 1
        assert data["high_findings"] >= 2

    async def test_unauthorized_access(self, async_client):
        """Test that endpoints require authentication."""
        response = await async_client.get("/api/v1/scans/")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_invalid_scan_id_format(self, async_client, test_user, auth_token):
        """Test endpoints with invalid scan ID format."""
        response = await async_client.get(
            "/api/v1/scans/invalid-id",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_scan_not_found_for_findings(self, async_client, test_user, auth_token):
        """Test findings endpoint with non-existent scan ID."""
        fake_id = str(uuid4())
        response = await async_client.get(
            f"/api/v1/scans/{fake_id}/findings",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_scan_not_found_for_reports(self, async_client, test_user, auth_token):
        """Test reports endpoint with non-existent scan ID."""
        fake_id = str(uuid4())
        response = await async_client.get(
            f"/api/v1/scans/{fake_id}/reports",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
