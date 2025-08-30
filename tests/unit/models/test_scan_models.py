"""Unit tests for Scan models."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.models.scan import Scan, ScanFinding, ScanReport, ScanSeverity, ScanStatus, ScanType


class TestScanModel:
    """Test cases for Scan model."""

    def test_scan_creation(self):
        """Test basic scan creation."""
        scan = Scan(
            name="Security Assessment",
            scan_type=ScanType.PYRIT_ORCHESTRATOR,
            description="Comprehensive security scan",
            target_config={"endpoint": "https://api.example.com"},
            scan_config={"max_requests": 100, "timeout": 30},
            parameters={"intensity": "medium"},
            tags=["security", "automated"],
            created_by="testuser",
        )

        assert scan.name == "Security Assessment"
        assert scan.scan_type == ScanType.PYRIT_ORCHESTRATOR
        assert scan.status == ScanStatus.PENDING  # Default
        assert scan.description == "Comprehensive security scan"
        assert scan.target_config["endpoint"] == "https://api.example.com"
        assert scan.scan_config["max_requests"] == 100
        assert scan.parameters["intensity"] == "medium"
        assert scan.tags == ["security", "automated"]
        assert scan.progress == 0  # Default
        assert scan.findings_count == 0  # Default

    def test_scan_type_enum_values(self):
        """Test ScanType enum values."""
        assert ScanType.PYRIT_ORCHESTRATOR == "pyrit_orchestrator"
        assert ScanType.GARAK_PROBE == "garak_probe"
        assert ScanType.CUSTOM_SCAN == "custom_scan"
        assert ScanType.BENCHMARK_TEST == "benchmark_test"
        assert ScanType.ADVERSARIAL_TEST == "adversarial_test"

    def test_scan_status_enum_values(self):
        """Test ScanStatus enum values."""
        assert ScanStatus.PENDING == "pending"
        assert ScanStatus.INITIALIZING == "initializing"
        assert ScanStatus.RUNNING == "running"
        assert ScanStatus.COMPLETED == "completed"
        assert ScanStatus.FAILED == "failed"
        assert ScanStatus.CANCELLED == "cancelled"
        assert ScanStatus.TIMEOUT == "timeout"

    def test_scan_default_values(self):
        """Test scan default values."""
        scan = Scan(name="Minimal Scan", scan_type=ScanType.GARAK_PROBE, created_by="testuser")

        assert scan.status == ScanStatus.PENDING
        assert scan.target_config == {}
        assert scan.scan_config == {}
        assert scan.parameters == {}
        assert scan.tags == []
        assert scan.progress == 0
        assert scan.total_tests == 0
        assert scan.completed_tests == 0
        assert scan.failed_tests == 0
        assert scan.findings_count == 0
        assert scan.critical_findings == 0
        assert scan.high_findings == 0
        assert scan.medium_findings == 0
        assert scan.low_findings == 0

    def test_scan_findings_summary(self):
        """Test scan findings summary fields."""
        scan = Scan(
            name="Findings Test",
            scan_type=ScanType.PYRIT_ORCHESTRATOR,
            findings_count=25,
            critical_findings=2,
            high_findings=5,
            medium_findings=10,
            low_findings=8,
            created_by="testuser",
        )

        assert scan.findings_count == 25
        assert scan.critical_findings == 2
        assert scan.high_findings == 5
        assert scan.medium_findings == 10
        assert scan.low_findings == 8

        # Verify totals match
        total_by_severity = scan.critical_findings + scan.high_findings + scan.medium_findings + scan.low_findings
        assert total_by_severity == 25

    def test_scan_progress_tracking(self):
        """Test scan progress tracking fields."""
        scan = Scan(
            name="Progress Test",
            scan_type=ScanType.BENCHMARK_TEST,
            progress=65,
            current_phase="Vulnerability Detection",
            total_tests=1000,
            completed_tests=650,
            failed_tests=10,
            created_by="testuser",
        )

        assert scan.progress == 65
        assert scan.current_phase == "Vulnerability Detection"
        assert scan.total_tests == 1000
        assert scan.completed_tests == 650
        assert scan.failed_tests == 10

    def test_scan_quality_metrics(self):
        """Test scan quality metrics."""
        scan = Scan(
            name="Quality Test",
            scan_type=ScanType.ADVERSARIAL_TEST,
            overall_score=85.5,
            risk_score=7.2,
            confidence_score=0.92,
            created_by="testuser",
        )

        assert scan.overall_score == 85.5
        assert scan.risk_score == 7.2
        assert scan.confidence_score == 0.92

    def test_scan_error_handling(self):
        """Test scan error handling fields."""
        error_details = {
            "error_code": "CONN_TIMEOUT",
            "stack_trace": "...",
            "retry_count": 3,
            "last_attempt": "2025-01-01T12:00:00Z",
        }

        scan = Scan(
            name="Error Test",
            scan_type=ScanType.CUSTOM_SCAN,
            error_message="Connection timeout after 30 seconds",
            error_details=error_details,
            created_by="testuser",
        )

        assert scan.error_message == "Connection timeout after 30 seconds"
        assert scan.error_details["error_code"] == "CONN_TIMEOUT"
        assert scan.error_details["retry_count"] == 3

    def test_scan_repr(self):
        """Test scan string representation."""
        scan = Scan(
            name="Test Scan", scan_type=ScanType.PYRIT_ORCHESTRATOR, status=ScanStatus.RUNNING, created_by="testuser"
        )
        scan.id = "scan-id-123"

        repr_str = repr(scan)
        assert "scan-id-123" in repr_str
        assert "Test Scan" in repr_str
        assert "pyrit_orchestrator" in repr_str
        assert "running" in repr_str


class TestScanFindingModel:
    """Test cases for ScanFinding model."""

    def test_scan_finding_creation(self):
        """Test basic scan finding creation."""
        scan_id = str(uuid4())
        finding = ScanFinding(
            scan_id=scan_id,
            title="Database Input Validation Issue",
            description="User input is not properly sanitized",
            severity=ScanSeverity.HIGH,
            category="injection",
            vulnerability_type="sql_injection",
            confidence_score=0.95,
            created_by="testuser",
        )

        assert finding.scan_id == scan_id
        assert finding.title == "Database Input Validation Issue"
        assert finding.description == "User input is not properly sanitized"
        assert finding.severity == ScanSeverity.HIGH
        assert finding.category == "injection"
        assert finding.vulnerability_type == "sql_injection"
        assert finding.confidence_score == 0.95

    def test_scan_severity_enum_values(self):
        """Test ScanSeverity enum values."""
        assert ScanSeverity.INFO == "info"
        assert ScanSeverity.LOW == "low"
        assert ScanSeverity.MEDIUM == "medium"
        assert ScanSeverity.HIGH == "high"
        assert ScanSeverity.CRITICAL == "critical"

    def test_scan_finding_default_values(self):
        """Test scan finding default values."""
        scan_id = str(uuid4())
        finding = ScanFinding(
            scan_id=scan_id,
            title="Test Finding",
            description="Test description",
            severity=ScanSeverity.MEDIUM,
            category="test",
            vulnerability_type="test_vuln",
            created_by="testuser",
        )

        assert finding.confidence_score == 0.0  # Default
        assert finding.evidence == {}  # Default
        assert finding.references == []  # Default
        assert finding.status == "open"  # Default
        assert finding.false_positive is False  # Default
        assert finding.verified is False  # Default
        assert finding.finding_metadata == {}  # Default

    def test_scan_finding_technical_details(self):
        """Test scan finding technical details."""
        scan_id = str(uuid4())
        evidence = {
            "request": "GET /api/users?id=1' OR 1=1--",
            "response": 'HTTP/1.1 200 OK\n{"users": [...]}',
            "payload": "1' OR 1=1--",
        }

        finding = ScanFinding(
            scan_id=scan_id,
            title="Database Query Issue",
            description="Database query handling security issue",
            severity=ScanSeverity.CRITICAL,
            category="injection",
            vulnerability_type="blind_sql_injection",
            affected_component="user_api",
            attack_vector="query_parameter",
            evidence=evidence,
            proof_of_concept="Payload: 1' OR 1=1--",
            confidence_score=0.98,
            created_by="testuser",
        )

        assert finding.affected_component == "user_api"
        assert finding.attack_vector == "query_parameter"
        assert finding.evidence["request"] == "GET /api/users?id=1' OR 1=1--"
        assert finding.proof_of_concept == "Payload: 1' OR 1=1--"

    def test_scan_finding_scoring(self):
        """Test scan finding scoring fields."""
        scan_id = str(uuid4())
        finding = ScanFinding(
            scan_id=scan_id,
            title="Output Encoding Issue",
            description="Reflected cross-site scripting",
            severity=ScanSeverity.HIGH,
            category="xss",
            vulnerability_type="reflected_xss",
            cvss_score=7.4,
            confidence_score=0.88,
            impact_score=6.5,
            exploitability_score=8.2,
            created_by="testuser",
        )

        assert finding.cvss_score == 7.4
        assert finding.confidence_score == 0.88
        assert finding.impact_score == 6.5
        assert finding.exploitability_score == 8.2

    def test_scan_finding_remediation(self):
        """Test scan finding remediation fields."""
        scan_id = str(uuid4())
        # Test data: Use approved security reference domains for testing
        # These are legitimate security resources, not user-controlled URLs
        approved_test_references = [
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://owasp.org/www-community/attacks/SQL_Injection",
        ]
        references = approved_test_references

        finding = ScanFinding(
            scan_id=scan_id,
            title="SQL Injection",
            description="SQL injection vulnerability",
            severity=ScanSeverity.HIGH,
            category="injection",
            vulnerability_type="sql_injection",
            remediation="Use parameterized queries and input validation",
            references=references,
            created_by="testuser",
        )

        assert "parameterized queries" in finding.remediation
        assert len(finding.references) == 2
        # Validate references are proper URLs with expected domains
        from urllib.parse import urlparse

        ref0_parsed = urlparse(finding.references[0])
        ref1_parsed = urlparse(finding.references[1])
        assert ref0_parsed.netloc == "cwe.mitre.org"
        assert ref1_parsed.netloc == "owasp.org"

    def test_scan_finding_status_tracking(self):
        """Test scan finding status tracking."""
        scan_id = str(uuid4())

        # False positive finding
        false_positive = ScanFinding(
            scan_id=scan_id,
            title="False Positive Test",
            description="This is actually a false positive",
            severity=ScanSeverity.MEDIUM,
            category="test",
            vulnerability_type="false_positive",
            status="closed",
            false_positive=True,
            verified=False,
            created_by="testuser",
        )

        # Verified finding
        verified_finding = ScanFinding(
            scan_id=scan_id,
            title="Verified Vulnerability",
            description="This has been verified",
            severity=ScanSeverity.HIGH,
            category="injection",
            vulnerability_type="sql_injection",
            status="confirmed",
            false_positive=False,
            verified=True,
            created_by="testuser",
        )

        assert false_positive.false_positive is True
        assert false_positive.verified is False
        assert false_positive.status == "closed"

        assert verified_finding.false_positive is False
        assert verified_finding.verified is True
        assert verified_finding.status == "confirmed"

    def test_scan_finding_repr(self):
        """Test scan finding string representation."""
        scan_id = str(uuid4())
        finding = ScanFinding(
            scan_id=scan_id,
            title="Test Finding",
            description="Test description",
            severity=ScanSeverity.HIGH,
            category="test",
            vulnerability_type="test_vuln",
            created_by="testuser",
        )
        finding.id = "finding-id-123"

        repr_str = repr(finding)
        assert "finding-id-123" in repr_str
        assert scan_id in repr_str
        assert "high" in repr_str


class TestScanReportModel:
    """Test cases for ScanReport model."""

    def test_scan_report_creation(self):
        """Test basic scan report creation."""
        scan_id = str(uuid4())
        content = {
            "executive_summary": "Security assessment completed",
            "findings": [],
            "recommendations": ["Implement input validation"],
        }
        summary = {"total_findings": 5, "critical": 1, "high": 2, "medium": 1, "low": 1}

        report = ScanReport(
            scan_id=scan_id,
            name="Security Assessment Report",
            report_type="security_assessment",
            format="json",
            content=content,
            summary=summary,
            template_name="standard_template",
            generated_at=datetime.now(timezone.utc),
            created_by="testuser",
        )

        assert report.scan_id == scan_id
        assert report.name == "Security Assessment Report"
        assert report.report_type == "security_assessment"
        assert report.format == "json"
        assert report.content["executive_summary"] == "Security assessment completed"
        assert report.summary["total_findings"] == 5
        assert report.template_name == "standard_template"

    def test_scan_report_formats(self):
        """Test different scan report formats."""
        scan_id = str(uuid4())
        formats = ["json", "csv", "pdf", "html", "xml"]

        for fmt in formats:
            report = ScanReport(
                scan_id=scan_id,
                name=f"{fmt.upper()} Report",
                report_type="security_scan",
                format=fmt,
                summary={},
                generated_at=datetime.now(timezone.utc),
                created_by="testuser",
            )
            assert report.format == fmt
            assert fmt.upper() in report.name

    def test_scan_report_file_storage(self):
        """Test scan report file storage fields."""
        scan_id = str(uuid4())
        report = ScanReport(
            scan_id=scan_id,
            name="PDF Report",
            report_type="detailed_analysis",
            format="pdf",
            summary={},
            file_path="/reports/scan_123_report.pdf",
            file_size=1048576,  # 1MB
            file_hash="sha256:1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890",
            generated_at=datetime.now(timezone.utc),
            created_by="testuser",
        )

        assert report.file_path == "/reports/scan_123_report.pdf"
        assert report.file_size == 1048576
        assert report.file_hash == "sha256:1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890"

    def test_scan_report_access_control(self):
        """Test scan report access control fields."""
        scan_id = str(uuid4())
        expiration = datetime(2025, 12, 31, 23, 59, 59)

        # Public report
        public_report = ScanReport(
            scan_id=scan_id,
            name="Public Report",
            report_type="summary",
            format="html",
            summary={},
            is_public=True,
            expires_at=expiration,
            generated_at=datetime.now(timezone.utc),
            created_by="testuser",
        )

        # Private report
        private_report = ScanReport(
            scan_id=scan_id,
            name="Private Report",
            report_type="detailed",
            format="json",
            summary={},
            is_public=False,
            generated_at=datetime.now(timezone.utc),
            created_by="testuser",
        )

        assert public_report.is_public is True
        assert public_report.expires_at == expiration
        assert private_report.is_public is False
        assert private_report.expires_at is None

    def test_scan_report_complex_content(self):
        """Test scan report with complex content structure."""
        scan_id = str(uuid4())
        complex_content = {
            "metadata": {"scan_duration": 1800, "target_count": 5, "test_count": 250},
            "executive_summary": {
                "risk_level": "Medium",
                "key_findings": [
                    "Input validation issue in user management",
                    "Authentication security enhancement needed",
                ],
            },
            "findings": [
                {
                    "id": "finding_001",
                    "title": "Database Input Issue",
                    "severity": "HIGH",
                    "description": "...",
                    "evidence": {...},
                }
            ],
            "recommendations": {
                "immediate": ["Fix input validation"],
                "short_term": ["Implement WAF"],
                "long_term": ["Security training"],
            },
            "appendices": {"methodology": "...", "tools_used": ["tool1", "tool2"]},
        }

        complex_summary = {
            "scan_metrics": {"duration_minutes": 30, "requests_sent": 1500, "responses_received": 1498},
            "finding_summary": {
                "total": 8,
                "by_severity": {"critical": 0, "high": 2, "medium": 3, "low": 3},
                "by_category": {"injection": 2, "xss": 1, "configuration": 5},
            },
            "coverage": {"endpoints_tested": 25, "parameters_tested": 150},
        }

        report = ScanReport(
            scan_id=scan_id,
            name="Comprehensive Security Report",
            report_type="comprehensive_assessment",
            format="json",
            content=complex_content,
            summary=complex_summary,
            generated_at=datetime.now(timezone.utc),
            created_by="testuser",
        )

        assert report.content["metadata"]["scan_duration"] == 1800
        assert len(report.content["findings"]) == 1
        assert report.summary["finding_summary"]["total"] == 8
        assert report.summary["coverage"]["endpoints_tested"] == 25

    def test_scan_report_repr(self):
        """Test scan report string representation."""
        scan_id = str(uuid4())
        report = ScanReport(
            scan_id=scan_id,
            name="Test Report",
            report_type="test_report",
            format="json",
            summary={},
            generated_at=datetime.now(timezone.utc),
            created_by="testuser",
        )
        report.id = "report-id-123"

        repr_str = repr(report)
        assert "report-id-123" in repr_str
        assert scan_id in repr_str
        assert "test_report" in repr_str
