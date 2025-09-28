"""Security Audit Service for comprehensive security assessment - Issue #124."""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import and_, desc, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.config import get_settings
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.models.mfa import MFADevice, MFAEvent
from app.models.oauth import OAuthAccessToken, OAuthApplication
from app.models.session import Session
from app.models.user import User
from app.repositories.audit_log_extensions import ExtendedAuditLogRepository

logger = get_logger(__name__)


class SecurityAuditReport:
    """Security audit report container."""

    def __init__(self, report_type: str):
        self.report_type = report_type
        self.generated_at = datetime.now(timezone.utc)
        self.findings: List[Dict[str, Any]] = []
        self.recommendations: List[Dict[str, Any]] = []
        self.risk_score = 0
        self.compliance_status = "unknown"

    def add_finding(self, severity: str, category: str, description: str, details: Dict[str, Any] = None):
        """Add a security finding to the report."""
        finding = {
            "severity": severity,
            "category": category,
            "description": description,
            "details": details or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.findings.append(finding)

        # Update risk score based on severity
        severity_scores = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        self.risk_score += severity_scores.get(severity, 0)

    def add_recommendation(self, priority: str, action: str, rationale: str):
        """Add a security recommendation to the report."""
        recommendation = {
            "priority": priority,
            "action": action,
            "rationale": rationale,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.recommendations.append(recommendation)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "report_type": self.report_type,
            "generated_at": self.generated_at.isoformat(),
            "risk_score": self.risk_score,
            "compliance_status": self.compliance_status,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "summary": {
                "total_findings": len(self.findings),
                "critical_findings": len([f for f in self.findings if f["severity"] == "critical"]),
                "high_findings": len([f for f in self.findings if f["severity"] == "high"]),
                "medium_findings": len([f for f in self.findings if f["severity"] == "medium"]),
                "low_findings": len([f for f in self.findings if f["severity"] == "low"]),
            },
        }


class AuthSecurityReport(SecurityAuditReport):
    """Authentication security audit report."""

    def __init__(self):
        super().__init__("authentication_security")


class AuthZReport(SecurityAuditReport):
    """Authorization control audit report."""

    def __init__(self):
        super().__init__("authorization_controls")


class DataProtectionReport(SecurityAuditReport):
    """Data protection audit report."""

    def __init__(self):
        super().__init__("data_protection")


class SecurityAuditService:
    """Comprehensive security audit service for ViolentUTF API."""

    def __init__(self, session: AsyncSession):
        """Initialize security audit service."""
        self.session = session
        self.settings = get_settings()
        self.audit_repo = ExtendedAuditLogRepository(session)
        self.logger = logger.bind(service="SecurityAuditService")

    async def conduct_comprehensive_audit(self) -> Dict[str, Any]:
        """Conduct comprehensive security audit of the entire system.

        Returns:
            Dictionary containing complete security audit results
        """
        self.logger.info("Starting comprehensive security audit")

        try:
            # Perform individual audit components
            auth_report = await self.analyze_authentication_security()
            authz_report = await self.assess_authorization_controls()
            data_report = await self.evaluate_data_protection()

            # Calculate overall security posture
            total_risk = auth_report.risk_score + authz_report.risk_score + data_report.risk_score

            # Determine overall compliance status
            critical_issues = (
                len([f for f in auth_report.findings if f["severity"] == "critical"])
                + len([f for f in authz_report.findings if f["severity"] == "critical"])
                + len([f for f in data_report.findings if f["severity"] == "critical"])
            )

            overall_compliance = "compliant" if critical_issues == 0 else "non_compliant"

            comprehensive_audit = {
                "audit_metadata": {
                    "conducted_at": datetime.now(timezone.utc).isoformat(),
                    "auditor": "SecurityAuditService v1.0",
                    "scope": "comprehensive_system_security",
                },
                "authentication_security": auth_report.to_dict(),
                "authorization_controls": authz_report.to_dict(),
                "data_protection": data_report.to_dict(),
                "overall_assessment": {
                    "total_risk_score": total_risk,
                    "compliance_status": overall_compliance,
                    "critical_issues": critical_issues,
                    "security_grade": self._calculate_security_grade(total_risk, critical_issues),
                },
                "audit_completeness": await self._assess_audit_completeness(),
                "immediate_actions": self._compile_immediate_actions([auth_report, authz_report, data_report]),
            }

            self.logger.info(
                "Comprehensive security audit completed", risk_score=total_risk, compliance=overall_compliance
            )

            return comprehensive_audit

        except Exception as e:
            self.logger.error("Comprehensive security audit failed", error=str(e))
            raise

    async def analyze_authentication_security(self) -> AuthSecurityReport:
        """Analyze authentication security mechanisms and policies.

        Returns:
            AuthSecurityReport with authentication security assessment
        """
        self.logger.info("Analyzing authentication security")

        report = AuthSecurityReport()

        try:
            # Analyze password policies
            await self._audit_password_policies(report)

            # Analyze MFA coverage
            await self._audit_mfa_coverage(report)

            # Analyze session management
            await self._audit_session_management(report)

            # Analyze JWT security
            await self._audit_jwt_security(report)

            # Analyze failed login tracking
            await self._audit_failed_login_tracking(report)

            # Determine compliance status
            critical_auth_issues = len([f for f in report.findings if f["severity"] == "critical"])
            report.compliance_status = "compliant" if critical_auth_issues == 0 else "non_compliant"

            self.logger.info(
                "Authentication security analysis completed",
                findings=len(report.findings),
                risk_score=report.risk_score,
            )

            return report

        except Exception as e:
            self.logger.error("Authentication security analysis failed", error=str(e))
            raise

    async def assess_authorization_controls(self) -> AuthZReport:
        """Assess authorization controls and RBAC effectiveness.

        Returns:
            AuthZReport with authorization control assessment
        """
        self.logger.info("Assessing authorization controls")

        report = AuthZReport()

        try:
            # Assess RBAC effectiveness
            await self._assess_rbac_effectiveness(report)

            # Analyze permission coverage
            await self._analyze_permission_coverage(report)

            # Review role assignments
            await self._review_role_assignments(report)

            # Check least privilege compliance
            await self._check_least_privilege_compliance(report)

            # Audit API authorization
            await self._audit_api_authorization(report)

            # Determine compliance status
            critical_authz_issues = len([f for f in report.findings if f["severity"] == "critical"])
            report.compliance_status = "compliant" if critical_authz_issues == 0 else "non_compliant"

            self.logger.info(
                "Authorization controls assessment completed",
                findings=len(report.findings),
                risk_score=report.risk_score,
            )

            return report

        except Exception as e:
            self.logger.error("Authorization controls assessment failed", error=str(e))
            raise

    async def evaluate_data_protection(self) -> DataProtectionReport:
        """Evaluate data protection mechanisms and compliance.

        Returns:
            DataProtectionReport with data protection assessment
        """
        self.logger.info("Evaluating data protection")

        report = DataProtectionReport()

        try:
            # Assess encryption coverage
            await self._assess_encryption_coverage(report)

            # Analyze data classification
            await self._analyze_data_classification(report)

            # Review access logging
            await self._review_access_logging(report)

            # Check retention policies
            await self._check_retention_policies(report)

            # Audit sensitive data handling
            await self._audit_sensitive_data_handling(report)

            # Determine compliance status
            critical_data_issues = len([f for f in report.findings if f["severity"] == "critical"])
            report.compliance_status = "compliant" if critical_data_issues == 0 else "non_compliant"

            self.logger.info(
                "Data protection evaluation completed", findings=len(report.findings), risk_score=report.risk_score
            )

            return report

        except Exception as e:
            self.logger.error("Data protection evaluation failed", error=str(e))
            raise

    async def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate regulatory compliance report.

        Returns:
            Dictionary containing compliance assessment
        """
        self.logger.info("Generating compliance report")

        try:
            comprehensive_audit = await self.conduct_comprehensive_audit()

            # Map findings to regulatory requirements
            regulatory_compliance = {
                "GDPR": await self._assess_gdpr_compliance(comprehensive_audit),
                "SOX": await self._assess_sox_compliance(comprehensive_audit),
                "PCI_DSS": await self._assess_pci_compliance(comprehensive_audit),
                "FISMA": await self._assess_fisma_compliance(comprehensive_audit),
            }

            # Generate compliance gaps
            security_gaps = []
            for regulation, assessment in regulatory_compliance.items():
                if not assessment["compliant"]:
                    security_gaps.extend(assessment["gaps"])

            # Create remediation plan
            remediation_plan = self._create_remediation_plan(security_gaps)

            # Assess overall risk
            risk_assessment = {
                "overall_risk_level": self._calculate_risk_level(
                    comprehensive_audit["overall_assessment"]["total_risk_score"]
                ),
                "business_impact": (
                    "high" if comprehensive_audit["overall_assessment"]["critical_issues"] > 0 else "medium"
                ),
                "likelihood": "medium",
                "risk_appetite": "low",
            }

            compliance_report = {
                "report_metadata": {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "scope": "regulatory_compliance_assessment",
                    "version": "1.0",
                },
                "regulatory_compliance": regulatory_compliance,
                "security_gaps": security_gaps,
                "remediation_plan": remediation_plan,
                "risk_assessment": risk_assessment,
                "audit_summary": comprehensive_audit["overall_assessment"],
            }

            self.logger.info("Compliance report generated successfully")
            return compliance_report

        except Exception as e:
            self.logger.error("Compliance report generation failed", error=str(e))
            raise

    # Private audit methods

    async def _audit_password_policies(self, report: AuthSecurityReport):
        """Audit password policy enforcement."""
        # Check if password policies are properly configured
        # This would integrate with the enhanced security functions

        # For now, add basic findings based on current implementation
        report.add_finding(
            "medium",
            "password_policy",
            "Password strength validation is implemented but could be enhanced",
            {"current_requirements": "8+ chars, upper, lower, digit, special"},
        )

        report.add_recommendation(
            "medium",
            "Enhance password policies with additional entropy requirements",
            "Current password policy meets basic requirements but could benefit from entropy-based validation",
        )

    async def _audit_mfa_coverage(self, report: AuthSecurityReport):
        """Audit MFA coverage and compliance."""
        # Get MFA devices and analyze coverage
        mfa_query = select(MFADevice).where(
            and_(MFADevice.is_deleted == False, MFADevice.is_active == True)
        )  # noqa: E712
        result = await self.session.execute(mfa_query)
        mfa_devices = result.scalars().all()

        # Get total users
        users_query = select(User).where(User.is_deleted == False)  # noqa: E712
        users_result = await self.session.execute(users_query)
        users = users_result.scalars().all()

        users_with_mfa = set(str(device.user_id) for device in mfa_devices)
        total_users = len(users)
        mfa_coverage = len(users_with_mfa) / total_users * 100 if total_users > 0 else 0

        if mfa_coverage < 80:
            report.add_finding(
                "high",
                "mfa_coverage",
                f"MFA coverage is {mfa_coverage:.1f}% (target: 80%)",
                {"coverage_percentage": mfa_coverage, "users_without_mfa": total_users - len(users_with_mfa)},
            )

        # Check admin users without MFA
        admin_users_without_mfa = []
        for user in users:
            if user.has_role("admin") and str(user.id) not in users_with_mfa:
                admin_users_without_mfa.append(user.username)

        if admin_users_without_mfa:
            report.add_finding(
                "critical",
                "admin_mfa_missing",
                f"{len(admin_users_without_mfa)} admin users do not have MFA enabled",
                {"admin_users": admin_users_without_mfa},
            )

    async def _audit_session_management(self, report: AuthSecurityReport):
        """Audit session management security."""
        # Get active sessions
        sessions_query = select(Session).where(Session.is_deleted == False)  # noqa: E712
        result = await self.session.execute(sessions_query)
        sessions = result.scalars().all()

        # Check for sessions without proper expiration
        sessions_without_expiry = [s for s in sessions if not s.expires_at]
        if sessions_without_expiry:
            report.add_finding(
                "medium",
                "session_expiration",
                f"{len(sessions_without_expiry)} sessions do not have expiration set",
                {"sessions_count": len(sessions_without_expiry)},
            )

        # Check for long-running sessions
        long_sessions = []
        now = datetime.now(timezone.utc)
        for session in sessions:
            if session.created_at and (now - session.created_at).days > 30:
                long_sessions.append(str(session.id))

        if long_sessions:
            report.add_finding(
                "medium",
                "long_running_sessions",
                f"{len(long_sessions)} sessions have been active for over 30 days",
                {"session_ids": long_sessions[:10]},  # Limit to first 10 for brevity
            )

    async def _audit_jwt_security(self, report: AuthSecurityReport):
        """Audit JWT token security configuration."""
        # Check JWT configuration from settings
        settings = self.settings

        # Validate algorithm
        if settings.ALGORITHM != "HS256":
            report.add_finding(
                "low",
                "jwt_algorithm",
                f"JWT algorithm is {settings.ALGORITHM}, consider using RS256 for enhanced security",
                {"current_algorithm": settings.ALGORITHM},
            )

        # Check token expiration times
        if settings.ACCESS_TOKEN_EXPIRE_MINUTES > 60:
            report.add_finding(
                "medium",
                "jwt_expiration",
                f"Access token expiration is {settings.ACCESS_TOKEN_EXPIRE_MINUTES} minutes (recommended: ≤60)",
                {"current_expiration": settings.ACCESS_TOKEN_EXPIRE_MINUTES},
            )

    async def _audit_failed_login_tracking(self, report: AuthSecurityReport):
        """Audit failed login attempt tracking and response."""
        # Get recent failed login attempts
        failed_logins_query = select(AuditLog).where(
            and_(
                AuditLog.action == "auth.login_failed",
                AuditLog.created_at >= datetime.now(timezone.utc) - timedelta(days=7),
            )
        )
        result = await self.session.execute(failed_logins_query)
        failed_logins = result.scalars().all()

        # Analyze patterns
        ip_attempts: Dict[str, int] = {}
        for log in failed_logins:
            if log.ip_address:
                ip_attempts[log.ip_address] = ip_attempts.get(log.ip_address, 0) + 1

        # Check for brute force patterns
        suspicious_ips = {ip: count for ip, count in ip_attempts.items() if count > 10}
        if suspicious_ips:
            report.add_finding(
                "high",
                "brute_force_attempts",
                f"{len(suspicious_ips)} IP addresses show potential brute force patterns",
                {"suspicious_ips": dict(list(suspicious_ips.items())[:5])},  # Limit for brevity
            )

    async def _assess_rbac_effectiveness(self, report: AuthZReport):
        """Assess Role-Based Access Control effectiveness."""
        # Get user role distribution
        users_query = select(User).where(User.is_deleted == False)  # noqa: E712
        result = await self.session.execute(users_query)
        users = result.scalars().all()

        # Analyze role distribution
        role_counts = {"admin": 0, "tester": 0, "viewer": 0}
        for user in users:
            for role in user.roles:
                if role in role_counts:
                    role_counts[role] += 1

        total_users = len(users)
        if total_users > 0:
            admin_percentage = role_counts["admin"] / total_users * 100

            if admin_percentage > 20:
                report.add_finding(
                    "medium",
                    "excessive_admin_users",
                    f"{admin_percentage:.1f}% of users have admin privileges (recommended: <20%)",
                    {"admin_percentage": admin_percentage, "admin_count": role_counts["admin"]},
                )

    async def _analyze_permission_coverage(self, report: AuthZReport):
        """Analyze permission coverage and gaps."""
        # This would be enhanced with actual permission mapping
        report.add_finding(
            "low",
            "permission_documentation",
            "Permission coverage analysis requires enhanced permission mapping",
            {"recommendation": "Implement detailed permission documentation"},
        )

    async def _review_role_assignments(self, report: AuthZReport):
        """Review role assignments for appropriateness."""
        # Get users with their last login
        users_query = select(User).where(User.is_deleted == False)  # noqa: E712
        result = await self.session.execute(users_query)
        users = result.scalars().all()

        # Find admin users who haven't logged in recently
        stale_admins = []
        for user in users:
            if user.has_role("admin") and user.last_login_at:
                days_since_login = (datetime.now(timezone.utc) - user.last_login_at).days
                if days_since_login > 90:
                    stale_admins.append({"username": user.username, "days_since_login": days_since_login})

        if stale_admins:
            report.add_finding(
                "medium",
                "stale_admin_accounts",
                f"{len(stale_admins)} admin users haven't logged in for >90 days",
                {"stale_admins": stale_admins[:5]},  # Limit for brevity
            )

    async def _check_least_privilege_compliance(self, report: AuthZReport):
        """Check compliance with least privilege principle."""
        # This would be enhanced with actual privilege usage analysis
        report.add_recommendation(
            "medium",
            "Implement privilege usage monitoring",
            "Monitor actual permission usage to identify over-privileged accounts",
        )

    async def _audit_api_authorization(self, report: AuthZReport):
        """Audit API authorization mechanisms."""
        # Get API keys
        api_keys_query = select(APIKey).where(APIKey.is_deleted == False)  # noqa: E712
        result = await self.session.execute(api_keys_query)
        api_keys = result.scalars().all()

        # Check for keys without expiration
        no_expiry_keys = [k for k in api_keys if not k.expires_at]
        if no_expiry_keys:
            report.add_finding(
                "medium",
                "api_key_expiration",
                f"{len(no_expiry_keys)} API keys do not have expiration dates",
                {"keys_without_expiry": len(no_expiry_keys)},
            )

    async def _assess_encryption_coverage(self, report: DataProtectionReport):
        """Assess data encryption coverage."""
        # This would be enhanced with actual encryption analysis
        report.add_finding(
            "medium",
            "encryption_coverage",
            "Field-level encryption not yet implemented for sensitive data",
            {"recommendation": "Implement application-level encryption for PII and sensitive fields"},
        )

    async def _analyze_data_classification(self, report: DataProtectionReport):
        """Analyze data classification and handling."""
        # This would analyze actual data classification
        report.add_recommendation(
            "high",
            "Implement data classification schema",
            "Establish formal data classification to ensure appropriate protection levels",
        )

    async def _review_access_logging(self, report: DataProtectionReport):
        """Review access logging completeness."""
        # Check audit log coverage
        recent_logs_query = select(func.count(AuditLog.id)).where(
            AuditLog.created_at >= datetime.now(timezone.utc) - timedelta(days=1)
        )
        result = await self.session.execute(recent_logs_query)
        recent_log_count = result.scalar()

        if recent_log_count and recent_log_count < 10:  # Arbitrary threshold
            report.add_finding(
                "medium",
                "audit_log_volume",
                f"Only {recent_log_count} audit logs generated in last 24 hours",
                {"log_count": recent_log_count},
            )

    async def _check_retention_policies(self, report: DataProtectionReport):
        """Check data retention policy compliance."""
        # Check for old audit logs
        old_logs_query = select(func.count(AuditLog.id)).where(
            AuditLog.created_at < datetime.now(timezone.utc) - timedelta(days=365)
        )
        result = await self.session.execute(old_logs_query)
        old_log_count = result.scalar()

        if old_log_count and old_log_count > 1000:  # Arbitrary threshold
            report.add_finding(
                "low",
                "audit_log_retention",
                f"{old_log_count} audit logs are older than 1 year",
                {"old_logs": old_log_count, "recommendation": "Implement automated log archival"},
            )

    async def _audit_sensitive_data_handling(self, report: DataProtectionReport):
        """Audit sensitive data handling practices."""
        # This would be enhanced with actual sensitive data scanning
        report.add_recommendation(
            "high", "Implement sensitive data scanning", "Regular scanning for sensitive data in logs and databases"
        )

    async def _assess_audit_completeness(self) -> Dict[str, Any]:
        """Assess completeness of audit trail."""
        # Get audit statistics
        total_logs = await self.session.execute(select(func.count(AuditLog.id)))
        total_count = total_logs.scalar()

        # Get recent activity
        recent_logs = await self.session.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.created_at >= datetime.now(timezone.utc) - timedelta(days=30)
            )
        )
        recent_count = recent_logs.scalar()

        return {
            "total_audit_logs": total_count,
            "recent_audit_logs": recent_count,
            "audit_coverage": "comprehensive" if recent_count and recent_count > 100 else "limited",
            "recommendations": [
                "Ensure all security events are properly logged",
                "Implement real-time audit log monitoring",
                "Regular audit log integrity verification",
            ],
        }

    def _calculate_security_grade(self, risk_score: int, critical_issues: int) -> str:
        """Calculate overall security grade."""
        if critical_issues > 0:
            return "F"
        elif risk_score > 50:
            return "D"
        elif risk_score > 30:
            return "C"
        elif risk_score > 15:
            return "B"
        else:
            return "A"

    def _calculate_risk_level(self, risk_score: int) -> str:
        """Calculate risk level based on score."""
        if risk_score > 40:
            return "critical"
        elif risk_score > 25:
            return "high"
        elif risk_score > 10:
            return "medium"
        else:
            return "low"

    def _compile_immediate_actions(self, reports: List[SecurityAuditReport]) -> List[Dict[str, str]]:
        """Compile immediate actions from all reports."""
        immediate_actions = []

        for report in reports:
            critical_findings = [f for f in report.findings if f["severity"] == "critical"]
            for finding in critical_findings:
                immediate_actions.append(
                    {
                        "action": f"Address {finding['category']}: {finding['description']}",
                        "category": finding["category"],
                        "severity": "critical",
                        "source_report": report.report_type,
                    }
                )

        return immediate_actions

    async def _assess_gdpr_compliance(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess GDPR compliance based on audit results."""
        # Simplified GDPR assessment
        gaps = []

        # Check for data protection measures
        data_findings = audit_results["data_protection"]["findings"]
        encryption_issues = [f for f in data_findings if "encryption" in f["category"]]
        if encryption_issues:
            gaps.append("Inadequate data encryption for personal data protection")

        return {
            "regulation": "GDPR",
            "compliant": len(gaps) == 0,
            "gaps": gaps,
            "compliance_percentage": max(0, 100 - len(gaps) * 20),
        }

    async def _assess_sox_compliance(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess SOX compliance based on audit results."""
        gaps = []

        # Check audit trail completeness
        if audit_results["audit_completeness"]["audit_coverage"] != "comprehensive":
            gaps.append("Incomplete audit trail for financial data access")

        return {
            "regulation": "SOX",
            "compliant": len(gaps) == 0,
            "gaps": gaps,
            "compliance_percentage": max(0, 100 - len(gaps) * 25),
        }

    async def _assess_pci_compliance(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess PCI DSS compliance based on audit results."""
        gaps = []

        # Check for strong authentication
        auth_findings = audit_results["authentication_security"]["findings"]
        critical_auth = [f for f in auth_findings if f["severity"] == "critical"]
        if critical_auth:
            gaps.append("Critical authentication security issues present")

        return {
            "regulation": "PCI_DSS",
            "compliant": len(gaps) == 0,
            "gaps": gaps,
            "compliance_percentage": max(0, 100 - len(gaps) * 30),
        }

    async def _assess_fisma_compliance(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess FISMA compliance based on audit results."""
        gaps = []

        # Check overall security posture
        if audit_results["overall_assessment"]["security_grade"] not in ["A", "B"]:
            gaps.append("Security posture does not meet FISMA requirements")

        return {
            "regulation": "FISMA",
            "compliant": len(gaps) == 0,
            "gaps": gaps,
            "compliance_percentage": max(0, 100 - len(gaps) * 35),
        }

    def _create_remediation_plan(self, security_gaps: List[str]) -> Dict[str, Any]:
        """Create security gap remediation plan."""
        return {
            "immediate_actions": security_gaps[:3],  # Top 3 priorities
            "short_term_goals": security_gaps[3:8],  # Next 5 items
            "long_term_objectives": security_gaps[8:],  # Remaining items
            "estimated_timeline": "3-6 months for complete remediation",
        }
