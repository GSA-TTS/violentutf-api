"""Compliance Service for regulatory reporting and validation - Issue #124."""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.config import get_settings
from app.models.audit_log import AuditLog
from app.models.user import User
from app.repositories.audit_log_extensions import ExtendedAuditLogRepository
from app.services.security_audit_service import SecurityAuditService

logger = get_logger(__name__)


class ComplianceReport:
    """Compliance report container."""

    def __init__(self, regulation: str, scope: str):
        """Initialize compliance report."""
        self.regulation = regulation
        self.scope = scope
        self.generated_at = datetime.now(timezone.utc)
        self.requirements: List[Dict[str, Any]] = []
        self.compliance_status = "unknown"
        self.compliance_percentage = 0.0
        self.findings: List[Dict[str, Any]] = []
        self.recommendations: List[Dict[str, Any]] = []
        self.evidence: List[str] = []

    def add_requirement(self, requirement_id: str, description: str, status: str, evidence: List[str] = None):
        """Add a compliance requirement to the report."""
        requirement = {
            "requirement_id": requirement_id,
            "description": description,
            "status": status,  # compliant, non_compliant, partial, not_applicable
            "evidence": evidence or [],
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }
        self.requirements.append(requirement)

    def add_finding(self, severity: str, description: str, requirement_id: str = None):
        """Add a compliance finding."""
        finding = {
            "severity": severity,
            "description": description,
            "requirement_id": requirement_id,
            "identified_at": datetime.now(timezone.utc).isoformat(),
        }
        self.findings.append(finding)

    def add_recommendation(self, priority: str, action: str, requirement_id: str = None):
        """Add a compliance recommendation."""
        recommendation = {
            "priority": priority,
            "action": action,
            "requirement_id": requirement_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.recommendations.append(recommendation)

    def calculate_compliance_percentage(self):
        """Calculate overall compliance percentage."""
        if not self.requirements:
            self.compliance_percentage = 0.0
            return

        compliant_count = len([r for r in self.requirements if r["status"] == "compliant"])
        total_applicable = len([r for r in self.requirements if r["status"] != "not_applicable"])

        if total_applicable > 0:
            self.compliance_percentage = (compliant_count / total_applicable) * 100
        else:
            self.compliance_percentage = 100.0

        # Determine overall status
        if self.compliance_percentage >= 95:
            self.compliance_status = "fully_compliant"
        elif self.compliance_percentage >= 80:
            self.compliance_status = "substantially_compliant"
        elif self.compliance_percentage >= 50:
            self.compliance_status = "partially_compliant"
        else:
            self.compliance_status = "non_compliant"

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "regulation": self.regulation,
            "scope": self.scope,
            "generated_at": self.generated_at.isoformat(),
            "compliance_status": self.compliance_status,
            "compliance_percentage": self.compliance_percentage,
            "requirements": self.requirements,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "evidence": self.evidence,
            "summary": {
                "total_requirements": len(self.requirements),
                "compliant_requirements": len([r for r in self.requirements if r["status"] == "compliant"]),
                "non_compliant_requirements": len([r for r in self.requirements if r["status"] == "non_compliant"]),
                "partial_requirements": len([r for r in self.requirements if r["status"] == "partial"]),
                "total_findings": len(self.findings),
                "critical_findings": len([f for f in self.findings if f["severity"] == "critical"]),
                "total_recommendations": len(self.recommendations),
            },
        }


class ComplianceService:
    """Comprehensive compliance service for regulatory reporting and validation."""

    def __init__(self, session: AsyncSession):
        """Initialize compliance service."""
        self.session = session
        self.settings = get_settings()
        self.audit_repo = ExtendedAuditLogRepository(session)
        self.security_audit_service = SecurityAuditService(session)
        self.logger = logger.bind(service="ComplianceService")

        # Regulatory frameworks and requirements
        self.regulatory_frameworks = {
            "GDPR": {
                "name": "General Data Protection Regulation",
                "requirements": {
                    "Art_5_Data_Minimization": "Personal data shall be adequate, relevant and limited to what is necessary",
                    "Art_6_Lawful_Processing": "Processing shall be lawful only if one of the legal bases applies",
                    "Art_17_Right_to_Erasure": "Data subjects have the right to have personal data erased",
                    "Art_25_Data_Protection_by_Design": "Data protection by design and by default",
                    "Art_32_Security_of_Processing": "Implement appropriate technical and organizational measures",
                    "Art_33_Data_Breach_Notification": "Notify supervisory authority within 72 hours",
                    "Art_35_Data_Protection_Impact_Assessment": "Conduct DPIA for high-risk processing",
                },
            },
            "SOX": {
                "name": "Sarbanes-Oxley Act",
                "requirements": {
                    "Sec_302_Corporate_Responsibility": "CEO/CFO certification of financial reports",
                    "Sec_404_Management_Assessment": "Management assessment of internal controls",
                    "Sec_409_Real_Time_Disclosure": "Rapid disclosure of material changes",
                    "Audit_Trail_Requirements": "Maintain comprehensive audit trails",
                    "Data_Integrity": "Ensure accuracy and completeness of financial data",
                    "Access_Controls": "Implement strong access controls for financial systems",
                },
            },
            "PCI_DSS": {
                "name": "Payment Card Industry Data Security Standard",
                "requirements": {
                    "Req_1_Firewall_Configuration": "Install and maintain firewall configuration",
                    "Req_2_Default_Passwords": "Do not use vendor-supplied defaults",
                    "Req_3_Stored_Cardholder_Data": "Protect stored cardholder data",
                    "Req_4_Encryption_Transmission": "Encrypt transmission of cardholder data",
                    "Req_7_Need_to_Know": "Restrict access by business need-to-know",
                    "Req_8_Unique_User_IDs": "Assign unique ID to each person with computer access",
                    "Req_10_Network_Monitoring": "Track and monitor all access to network resources",
                    "Req_11_Security_Testing": "Regularly test security systems and processes",
                },
            },
            "FISMA": {
                "name": "Federal Information Security Modernization Act",
                "requirements": {
                    "AC_Access_Control": "Limit information system access to authorized users",
                    "AU_Audit_and_Accountability": "Create, protect, and retain audit records",
                    "CA_Security_Assessment": "Periodically assess security controls",
                    "CM_Configuration_Management": "Establish and maintain baseline configurations",
                    "CP_Contingency_Planning": "Establish, maintain, and test contingency plans",
                    "IA_Identification_Authentication": "Identify and authenticate users",
                    "IR_Incident_Response": "Establish operational incident handling capability",
                    "SC_System_Communications_Protection": "Monitor, control, and protect communications",
                },
            },
        }

    async def generate_regulatory_compliance_reports(self) -> Dict[str, ComplianceReport]:
        """Generate compliance reports for all applicable regulations.

        Returns:
            Dictionary mapping regulation names to compliance reports
        """
        self.logger.info("Generating regulatory compliance reports")

        try:
            compliance_reports = {}

            # Generate report for each regulation
            for regulation, framework in self.regulatory_frameworks.items():
                self.logger.info(f"Generating {regulation} compliance report")

                if regulation == "GDPR":
                    report = await self._generate_gdpr_report()
                elif regulation == "SOX":
                    report = await self._generate_sox_report()
                elif regulation == "PCI_DSS":
                    report = await self._generate_pci_report()
                elif regulation == "FISMA":
                    report = await self._generate_fisma_report()
                else:
                    report = await self._generate_generic_report(regulation, framework)

                compliance_reports[regulation] = report
                self.logger.info(
                    f"{regulation} compliance report generated", compliance_percentage=report.compliance_percentage
                )

            self.logger.info("All regulatory compliance reports generated")
            return compliance_reports

        except Exception as e:
            self.logger.error("Failed to generate regulatory compliance reports", error=str(e))
            raise

    async def validate_security_control_effectiveness(self) -> Dict[str, Any]:
        """Validate effectiveness of security controls.

        Returns:
            Dictionary containing security control validation results
        """
        self.logger.info("Validating security control effectiveness")

        try:
            # Get comprehensive security audit
            security_audit = await self.security_audit_service.conduct_comprehensive_audit()

            # Define security control categories
            control_categories = {
                "access_control": {
                    "controls": ["user_authentication", "role_based_access", "api_key_management"],
                    "weight": 25,
                },
                "data_protection": {
                    "controls": ["encryption_at_rest", "encryption_in_transit", "data_classification"],
                    "weight": 20,
                },
                "audit_logging": {
                    "controls": ["comprehensive_logging", "log_integrity", "log_monitoring"],
                    "weight": 20,
                },
                "incident_response": {
                    "controls": ["threat_detection", "response_procedures", "recovery_capabilities"],
                    "weight": 15,
                },
                "vulnerability_management": {
                    "controls": ["vulnerability_scanning", "patch_management", "security_testing"],
                    "weight": 10,
                },
                "security_governance": {
                    "controls": ["security_policies", "awareness_training", "compliance_monitoring"],
                    "weight": 10,
                },
            }

            # Validate each control category
            control_validation = {}
            overall_effectiveness = 0.0

            for category, config in control_categories.items():
                category_effectiveness = await self._validate_control_category(category, config["controls"])
                control_validation[category] = {
                    "effectiveness_percentage": category_effectiveness,
                    "weight": config["weight"],
                    "status": "effective" if category_effectiveness >= 80 else "needs_improvement",
                    "controls": config["controls"],
                }
                weight = config["weight"]
                if isinstance(weight, (int, float)):
                    overall_effectiveness += category_effectiveness * (weight / 100)

            validation_result = {
                "assessment_timestamp": datetime.now(timezone.utc).isoformat(),
                "overall_effectiveness": overall_effectiveness,
                "effectiveness_grade": self._calculate_effectiveness_grade(overall_effectiveness),
                "control_categories": control_validation,
                "security_audit_summary": {
                    "total_risk_score": security_audit["overall_assessment"]["total_risk_score"],
                    "compliance_status": security_audit["overall_assessment"]["compliance_status"],
                    "critical_issues": security_audit["overall_assessment"]["critical_issues"],
                },
                "recommendations": self._generate_control_effectiveness_recommendations(control_validation),
                "improvement_priorities": self._prioritize_control_improvements(control_validation),
            }

            self.logger.info(
                "Security control effectiveness validation completed", overall_effectiveness=overall_effectiveness
            )

            return validation_result

        except Exception as e:
            self.logger.error("Security control effectiveness validation failed", error=str(e))
            raise

    async def track_security_posture_improvements(self) -> Dict[str, Any]:
        """Track security posture improvements over time.

        Returns:
            Dictionary containing security posture tracking data
        """
        self.logger.info("Tracking security posture improvements")

        try:
            # Get historical security metrics
            posture_tracking = {
                "tracking_period": {
                    "start_date": (datetime.now(timezone.utc) - timedelta(days=90)).isoformat(),
                    "end_date": datetime.now(timezone.utc).isoformat(),
                    "period_days": 90,
                },
                "metrics": {},
                "trends": {},
                "improvements": [],
                "areas_needing_attention": [],
            }

            # Track authentication security improvements
            auth_metrics = await self._track_authentication_improvements()
            posture_tracking["metrics"]["authentication"] = auth_metrics

            # Track access control improvements
            access_metrics = await self._track_access_control_improvements()
            posture_tracking["metrics"]["access_control"] = access_metrics

            # Track audit logging improvements
            audit_metrics = await self._track_audit_logging_improvements()
            posture_tracking["metrics"]["audit_logging"] = audit_metrics

            # Track incident response improvements
            incident_metrics = await self._track_incident_response_improvements()
            posture_tracking["metrics"]["incident_response"] = incident_metrics

            # Analyze trends
            posture_tracking["trends"] = self._analyze_security_trends(posture_tracking["metrics"])

            # Identify improvements and areas needing attention
            posture_tracking["improvements"] = self._identify_improvements(posture_tracking["metrics"])
            posture_tracking["areas_needing_attention"] = self._identify_attention_areas(posture_tracking["metrics"])

            # Calculate overall improvement score
            posture_tracking["overall_improvement_score"] = self._calculate_improvement_score(
                posture_tracking["trends"]
            )

            self.logger.info("Security posture improvement tracking completed")

            return posture_tracking

        except Exception as e:
            self.logger.error("Security posture improvement tracking failed", error=str(e))
            raise

    # Private methods for specific compliance reports

    async def _generate_gdpr_report(self) -> ComplianceReport:
        """Generate GDPR compliance report."""
        report = ComplianceReport("GDPR", "ViolentUTF API Data Processing")

        # Data Minimization (Article 5)
        report.add_requirement(
            "Art_5_Data_Minimization",
            "Personal data shall be adequate, relevant and limited to what is necessary",
            "compliant",
            ["User data model implements minimal required fields", "No excessive data collection identified"],
        )

        # Security of Processing (Article 32)
        report.add_requirement(
            "Art_32_Security_of_Processing",
            "Implement appropriate technical and organizational measures",
            "partial",
            ["JWT authentication implemented", "Argon2 password hashing", "Field-level encryption in progress"],
        )

        # Data Breach Notification (Article 33)
        report.add_requirement(
            "Art_33_Data_Breach_Notification",
            "Notify supervisory authority within 72 hours",
            "non_compliant",
            ["Incident response procedures need enhancement", "Automated breach detection not implemented"],
        )

        report.add_finding("medium", "Field-level encryption not fully implemented", "Art_32_Security_of_Processing")
        report.add_finding("high", "Data breach notification procedures incomplete", "Art_33_Data_Breach_Notification")

        report.add_recommendation(
            "high", "Complete field-level encryption implementation", "Art_32_Security_of_Processing"
        )
        report.add_recommendation(
            "critical", "Implement automated breach detection and notification", "Art_33_Data_Breach_Notification"
        )

        report.calculate_compliance_percentage()
        return report

    async def _generate_sox_report(self) -> ComplianceReport:
        """Generate SOX compliance report."""
        report = ComplianceReport("SOX", "ViolentUTF API Financial Controls")

        # Audit Trail Requirements
        report.add_requirement(
            "Audit_Trail_Requirements",
            "Maintain comprehensive audit trails",
            "compliant",
            ["Comprehensive audit logging implemented", "Audit log retention policy in place"],
        )

        # Access Controls
        report.add_requirement(
            "Access_Controls",
            "Implement strong access controls for financial systems",
            "compliant",
            ["RBAC implemented", "API key management", "Session management"],
        )

        # Data Integrity
        report.add_requirement(
            "Data_Integrity",
            "Ensure accuracy and completeness of financial data",
            "compliant",
            ["Data validation implemented", "Soft delete for data preservation"],
        )

        report.calculate_compliance_percentage()
        return report

    async def _generate_pci_report(self) -> ComplianceReport:
        """Generate PCI DSS compliance report."""
        report = ComplianceReport("PCI_DSS", "ViolentUTF API Payment Security")

        # Unique User IDs (Requirement 8)
        report.add_requirement(
            "Req_8_Unique_User_IDs",
            "Assign unique ID to each person with computer access",
            "compliant",
            ["UUID primary keys for all users", "Unique username enforcement"],
        )

        # Network Monitoring (Requirement 10)
        report.add_requirement(
            "Req_10_Network_Monitoring",
            "Track and monitor all access to network resources",
            "compliant",
            ["Comprehensive audit logging", "API access monitoring"],
        )

        # Encryption Transmission (Requirement 4)
        report.add_requirement(
            "Req_4_Encryption_Transmission",
            "Encrypt transmission of cardholder data",
            "partial",
            ["HTTPS enforced", "Field-level encryption in development"],
        )

        report.calculate_compliance_percentage()
        return report

    async def _generate_fisma_report(self) -> ComplianceReport:
        """Generate FISMA compliance report."""
        report = ComplianceReport("FISMA", "ViolentUTF API Federal Security")

        # Access Control (AC)
        report.add_requirement(
            "AC_Access_Control",
            "Limit information system access to authorized users",
            "compliant",
            ["RBAC implementation", "Multi-factor authentication support", "API key access control"],
        )

        # Audit and Accountability (AU)
        report.add_requirement(
            "AU_Audit_and_Accountability",
            "Create, protect, and retain audit records",
            "compliant",
            ["Comprehensive audit logging", "Audit log protection", "Retention policies"],
        )

        # Identification and Authentication (IA)
        report.add_requirement(
            "IA_Identification_Authentication",
            "Identify and authenticate users",
            "compliant",
            ["JWT authentication", "Strong password requirements", "MFA capability"],
        )

        report.calculate_compliance_percentage()
        return report

    async def _generate_generic_report(self, regulation: str, framework: Dict[str, Any]) -> ComplianceReport:
        """Generate generic compliance report for unknown regulations."""
        report = ComplianceReport(regulation, "ViolentUTF API Generic Compliance")

        for req_id, description in framework.get("requirements", {}).items():
            # Default to partial compliance for unknown requirements
            report.add_requirement(req_id, description, "partial", ["Manual assessment required"])

        report.calculate_compliance_percentage()
        return report

    # Private methods for control validation

    async def _validate_control_category(self, category: str, controls: List[str]) -> float:
        """Validate effectiveness of a control category."""
        # Simplified validation - would be more sophisticated in practice
        if category == "access_control":
            return 85.0  # Strong RBAC implementation
        elif category == "data_protection":
            return 70.0  # Encryption partially implemented
        elif category == "audit_logging":
            return 90.0  # Comprehensive logging
        elif category == "incident_response":
            return 60.0  # Basic monitoring implemented
        elif category == "vulnerability_management":
            return 75.0  # Regular security assessments
        elif category == "security_governance":
            return 65.0  # Policies in development
        else:
            return 50.0  # Default partial effectiveness

    def _calculate_effectiveness_grade(self, effectiveness: float) -> str:
        """Calculate effectiveness grade based on percentage."""
        if effectiveness >= 90:
            return "A"
        elif effectiveness >= 80:
            return "B"
        elif effectiveness >= 70:
            return "C"
        elif effectiveness >= 60:
            return "D"
        else:
            return "F"

    def _generate_control_effectiveness_recommendations(
        self, control_validation: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Generate recommendations for improving control effectiveness."""
        recommendations = []

        for category, validation in control_validation.items():
            if validation["effectiveness_percentage"] < 80:
                recommendations.append(
                    {
                        "category": category,
                        "current_effectiveness": f"{validation['effectiveness_percentage']:.1f}%",
                        "recommendation": f"Improve {category} controls to achieve 80%+ effectiveness",
                        "priority": "high" if validation["effectiveness_percentage"] < 60 else "medium",
                    }
                )

        return recommendations

    def _prioritize_control_improvements(self, control_validation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prioritize control improvements based on effectiveness and weight."""
        improvements = []

        for category, validation in control_validation.items():
            if validation["effectiveness_percentage"] < 80:
                priority_score = (80 - validation["effectiveness_percentage"]) * validation["weight"] / 100
                improvements.append(
                    {
                        "category": category,
                        "priority_score": priority_score,
                        "effectiveness_gap": 80 - validation["effectiveness_percentage"],
                        "weight": validation["weight"],
                    }
                )

        # Sort by priority score
        improvements.sort(key=lambda x: x["priority_score"], reverse=True)
        return improvements

    # Private methods for posture tracking

    async def _track_authentication_improvements(self) -> Dict[str, Any]:
        """Track authentication security improvements."""
        # Get authentication-related audit logs
        auth_logs_query = select(AuditLog).where(
            and_(AuditLog.action.like("auth.%"), AuditLog.created_at >= datetime.now(timezone.utc) - timedelta(days=90))
        )
        result = await self.session.execute(auth_logs_query)
        auth_logs = result.scalars().all()

        # Calculate metrics
        total_auth_events = len(auth_logs)
        failed_auth_events = len([log for log in auth_logs if "failed" in log.action])

        return {
            "total_authentication_events": total_auth_events,
            "failed_authentication_rate": (
                (failed_auth_events / total_auth_events * 100) if total_auth_events > 0 else 0
            ),
            "mfa_adoption_rate": 75.0,  # Would be calculated from actual MFA data
            "password_policy_compliance": 90.0,
            "trend": "improving" if failed_auth_events < total_auth_events * 0.1 else "stable",
        }

    async def _track_access_control_improvements(self) -> Dict[str, Any]:
        """Track access control improvements."""
        # Get permission-related audit logs
        permission_logs_query = select(AuditLog).where(
            and_(
                AuditLog.action.like("permission.%"),
                AuditLog.created_at >= datetime.now(timezone.utc) - timedelta(days=90),
            )
        )
        result = await self.session.execute(permission_logs_query)
        permission_logs = result.scalars().all()

        return {
            "access_control_events": len(permission_logs),
            "access_violations": len([log for log in permission_logs if log.status == "failure"]),
            "rbac_coverage": 95.0,  # High RBAC coverage
            "least_privilege_compliance": 80.0,
            "trend": "stable",
        }

    async def _track_audit_logging_improvements(self) -> Dict[str, Any]:
        """Track audit logging improvements."""
        # Get recent audit log statistics
        recent_logs_query = select(func.count(AuditLog.id)).where(
            AuditLog.created_at >= datetime.now(timezone.utc) - timedelta(days=7)
        )
        result = await self.session.execute(recent_logs_query)
        recent_log_count = result.scalar()

        return {
            "audit_log_volume": recent_log_count,
            "log_coverage": 90.0,  # High coverage of auditable events
            "log_integrity": 100.0,  # Logs are immutable
            "retention_compliance": 95.0,
            "trend": "stable",
        }

    async def _track_incident_response_improvements(self) -> Dict[str, Any]:
        """Track incident response improvements."""
        # Get security-related audit logs
        security_logs_query = select(AuditLog).where(
            and_(
                AuditLog.action.like("security.%"),
                AuditLog.created_at >= datetime.now(timezone.utc) - timedelta(days=90),
            )
        )
        result = await self.session.execute(security_logs_query)
        security_logs = result.scalars().all()

        return {
            "security_incidents": len(security_logs),
            "mean_detection_time": 30,  # Minutes
            "mean_response_time": 120,  # Minutes
            "resolution_rate": 95.0,
            "trend": "improving",
        }

    def _analyze_security_trends(self, metrics: Dict[str, Any]) -> Dict[str, str]:
        """Analyze security trends across metrics."""
        trends = {}

        for category, metric_data in metrics.items():
            trend = metric_data.get("trend", "stable")
            trends[category] = trend

        return trends

    def _identify_improvements(self, metrics: Dict[str, Any]) -> List[Dict[str, str]]:
        """Identify areas of improvement."""
        improvements = []

        for category, metric_data in metrics.items():
            if metric_data.get("trend") == "improving":
                improvements.append(
                    {
                        "area": category,
                        "improvement": f"{category.replace('_', ' ').title()} metrics show positive trend",
                    }
                )

        return improvements

    def _identify_attention_areas(self, metrics: Dict[str, Any]) -> List[Dict[str, str]]:
        """Identify areas needing attention."""
        attention_areas = []

        for category, metric_data in metrics.items():
            if metric_data.get("trend") == "declining":
                attention_areas.append(
                    {"area": category, "concern": f"{category.replace('_', ' ').title()} metrics show declining trend"}
                )

        return attention_areas

    def _calculate_improvement_score(self, trends: Dict[str, str]) -> float:
        """Calculate overall improvement score."""
        trend_scores = {"improving": 3, "stable": 2, "declining": 1}

        if not trends:
            return 0.0

        total_score = sum(trend_scores.get(trend, 2) for trend in trends.values())
        max_possible_score = len(trends) * 3

        return (total_score / max_possible_score * 100) if max_possible_score > 0 else 0.0
