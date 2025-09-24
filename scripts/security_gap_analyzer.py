#!/usr/bin/env python3
"""Security Gap Analyzer for ViolentUTF API - Issue #124.

This script provides comprehensive security gap analysis and assessment capabilities including:
- Security vulnerability identification
- Compliance requirement assessment
- Security improvement prioritization
- Remediation recommendations
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.config import get_settings
from app.db.session import get_db
from app.services.security_audit_service import SecurityAuditService
from app.services.security_monitoring_service import SecurityMonitoringService
from scripts.access_audit import AccessControlAuditor

logger = get_logger(__name__)


class SecurityGapAnalyzer:
    """Comprehensive security gap analysis and assessment system."""

    def __init__(self, session: AsyncSession):
        """Initialize security gap analyzer."""
        self.session = session
        self.settings = get_settings()
        self.audit_service = SecurityAuditService(session)
        self.monitoring_service = SecurityMonitoringService(session)
        self.access_auditor = AccessControlAuditor(session)
        self.analysis_timestamp = datetime.now(timezone.utc)

        # Security standards frameworks
        self.security_frameworks = {
            "OWASP_Top_10": {
                "A01_Broken_Access_Control": {"weight": 10, "category": "access_control"},
                "A02_Cryptographic_Failures": {"weight": 9, "category": "encryption"},
                "A03_Injection": {"weight": 8, "category": "input_validation"},
                "A04_Insecure_Design": {"weight": 7, "category": "architecture"},
                "A05_Security_Misconfiguration": {"weight": 6, "category": "configuration"},
                "A06_Vulnerable_Components": {"weight": 5, "category": "dependencies"},
                "A07_Authentication_Failures": {"weight": 4, "category": "authentication"},
                "A08_Software_Integrity_Failures": {"weight": 3, "category": "integrity"},
                "A09_Security_Logging_Failures": {"weight": 2, "category": "logging"},
                "A10_Server_Side_Request_Forgery": {"weight": 1, "category": "ssrf"},
            },
            "NIST_Cybersecurity_Framework": {
                "IDENTIFY": {"weight": 5, "category": "asset_management"},
                "PROTECT": {"weight": 5, "category": "access_control"},
                "DETECT": {"weight": 4, "category": "monitoring"},
                "RESPOND": {"weight": 3, "category": "incident_response"},
                "RECOVER": {"weight": 2, "category": "business_continuity"},
            },
            "ISO_27001": {
                "Information_Security_Policies": {"weight": 4, "category": "governance"},
                "Access_Control": {"weight": 5, "category": "access_control"},
                "Cryptography": {"weight": 4, "category": "encryption"},
                "Security_Incident_Management": {"weight": 3, "category": "incident_response"},
                "Supplier_Relationships": {"weight": 2, "category": "third_party"},
            },
        }

        # Gap severity levels
        self.gap_severity = {
            "critical": {"score": 10, "description": "Immediate action required"},
            "high": {"score": 7, "description": "High priority remediation"},
            "medium": {"score": 4, "description": "Medium priority improvement"},
            "low": {"score": 1, "description": "Low priority enhancement"},
        }

    async def identify_security_vulnerabilities(self) -> Dict[str, Any]:
        """Identify security vulnerabilities across the system.

        Returns:
            Dictionary containing vulnerability assessment
        """
        logger.info("Starting security vulnerability identification")

        try:
            vulnerabilities: Dict[str, Any] = {
                "assessment_timestamp": self.analysis_timestamp.isoformat(),
                "vulnerability_categories": {},
                "critical_vulnerabilities": [],
                "high_risk_vulnerabilities": [],
                "medium_risk_vulnerabilities": [],
                "low_risk_vulnerabilities": [],
                "total_vulnerabilities": 0,
                "risk_score": 0,
            }

            # Conduct comprehensive security audit
            _ = await self.audit_service.conduct_comprehensive_audit()  # Used for initialization

            # Analyze access control vulnerabilities
            access_vulns = await self._analyze_access_control_vulnerabilities()
            vulnerabilities["vulnerability_categories"]["access_control"] = access_vulns

            # Analyze authentication vulnerabilities
            auth_vulns = await self._analyze_authentication_vulnerabilities()
            vulnerabilities["vulnerability_categories"]["authentication"] = auth_vulns

            # Analyze encryption vulnerabilities
            crypto_vulns = await self._analyze_cryptographic_vulnerabilities()
            vulnerabilities["vulnerability_categories"]["cryptography"] = crypto_vulns

            # Analyze configuration vulnerabilities
            config_vulns = await self._analyze_configuration_vulnerabilities()
            vulnerabilities["vulnerability_categories"]["configuration"] = config_vulns

            # Analyze logging and monitoring vulnerabilities
            logging_vulns = await self._analyze_logging_vulnerabilities()
            vulnerabilities["vulnerability_categories"]["logging"] = logging_vulns

            # Categorize vulnerabilities by severity
            all_vulns = []
            for category, vulns in vulnerabilities["vulnerability_categories"].items():
                all_vulns.extend(vulns.get("vulnerabilities", []))

            for vuln in all_vulns:
                severity = vuln.get("severity", "low")
                if severity == "critical":
                    vulnerabilities["critical_vulnerabilities"].append(vuln)
                elif severity == "high":
                    vulnerabilities["high_risk_vulnerabilities"].append(vuln)
                elif severity == "medium":
                    vulnerabilities["medium_risk_vulnerabilities"].append(vuln)
                else:
                    vulnerabilities["low_risk_vulnerabilities"].append(vuln)

            # Calculate totals and risk score
            vulnerabilities["total_vulnerabilities"] = len(all_vulns)
            vulnerabilities["risk_score"] = self._calculate_vulnerability_risk_score(all_vulns)

            logger.info(
                "Security vulnerability identification completed",
                total_vulns=vulnerabilities["total_vulnerabilities"],
                risk_score=vulnerabilities["risk_score"],
            )

            return vulnerabilities

        except Exception as e:
            logger.error("Security vulnerability identification failed", error=str(e))
            raise

    async def assess_compliance_requirements(self) -> Dict[str, Any]:
        """Assess compliance against security frameworks and standards.

        Returns:
            Dictionary containing compliance assessment
        """
        logger.info("Starting compliance requirements assessment")

        try:
            compliance_assessment: Dict[str, Any] = {
                "assessment_timestamp": self.analysis_timestamp.isoformat(),
                "frameworks": {},
                "overall_compliance_score": 0,
                "compliance_gaps": [],
                "recommendations": [],
            }

            # Assess against each framework
            for framework_name, controls in self.security_frameworks.items():
                framework_assessment = await self._assess_framework_compliance(framework_name, controls)
                compliance_assessment["frameworks"][framework_name] = framework_assessment

            # Calculate overall compliance score
            total_frameworks = len(self.security_frameworks)
            total_score = sum(
                assessment["compliance_percentage"] for assessment in compliance_assessment["frameworks"].values()
            )
            compliance_assessment["overall_compliance_score"] = (
                total_score / total_frameworks if total_frameworks > 0 else 0
            )

            # Collect all compliance gaps
            for framework_assessment in compliance_assessment["frameworks"].values():
                compliance_assessment["compliance_gaps"].extend(framework_assessment.get("gaps", []))

            # Generate compliance recommendations
            compliance_assessment["recommendations"] = await self._generate_compliance_recommendations(
                compliance_assessment["compliance_gaps"]
            )

            logger.info(
                "Compliance requirements assessment completed",
                overall_score=compliance_assessment["overall_compliance_score"],
            )

            return compliance_assessment

        except Exception as e:
            logger.error("Compliance requirements assessment failed", error=str(e))
            raise

    async def prioritize_security_improvements(self) -> Dict[str, Any]:
        """Prioritize security improvements based on risk and impact.

        Returns:
            Dictionary containing prioritized improvement plan
        """
        logger.info("Starting security improvement prioritization")

        try:
            # Get vulnerability and compliance data
            vulnerabilities = await self.identify_security_vulnerabilities()
            compliance = await self.assess_compliance_requirements()

            # Analyze current security posture
            security_posture = await self._analyze_security_posture()

            # Create improvement prioritization matrix
            improvements: List[Dict[str, Any]] = []

            # Add critical vulnerabilities as highest priority
            for vuln in vulnerabilities["critical_vulnerabilities"]:
                improvements.append(
                    {
                        "type": "vulnerability_remediation",
                        "priority": "critical",
                        "title": vuln.get("title", "Critical Vulnerability"),
                        "description": vuln.get("description", ""),
                        "impact": "high",
                        "effort": self._estimate_remediation_effort(vuln),
                        "timeline": "immediate",
                        "category": vuln.get("category", "security"),
                    }
                )

            # Add high-impact compliance gaps
            for gap in compliance["compliance_gaps"]:
                if gap.get("impact", "medium") == "high":
                    improvements.append(
                        {
                            "type": "compliance_improvement",
                            "priority": "high",
                            "title": f"Address {gap.get('framework')} compliance gap",
                            "description": gap.get("description", ""),
                            "impact": gap.get("impact", "medium"),
                            "effort": self._estimate_compliance_effort(gap),
                            "timeline": "short_term",
                            "category": "compliance",
                        }
                    )

            # Add security posture enhancements
            for enhancement in security_posture.get("recommended_enhancements", []):
                improvements.append(
                    {
                        "type": "security_enhancement",
                        "priority": enhancement.get("priority", "medium"),
                        "title": enhancement.get("title", "Security Enhancement"),
                        "description": enhancement.get("description", ""),
                        "impact": enhancement.get("impact", "medium"),
                        "effort": enhancement.get("effort", "medium"),
                        "timeline": enhancement.get("timeline", "medium_term"),
                        "category": "enhancement",
                    }
                )

            # Sort by priority and impact
            priority_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            impact_order = {"high": 3, "medium": 2, "low": 1}

            improvements.sort(
                key=lambda x: (priority_order.get(x["priority"], 1), impact_order.get(x["impact"], 1)), reverse=True
            )

            # Create prioritized improvement plan
            improvement_plan = {
                "plan_timestamp": self.analysis_timestamp.isoformat(),
                "total_improvements": len(improvements),
                "immediate_actions": [i for i in improvements if i["priority"] == "critical"][:5],
                "short_term_goals": [i for i in improvements if i["priority"] == "high"][:10],
                "medium_term_objectives": [i for i in improvements if i["priority"] == "medium"][:15],
                "long_term_initiatives": [i for i in improvements if i["priority"] == "low"][:10],
                "estimated_timeline": self._estimate_overall_timeline(improvements),
                "resource_requirements": self._estimate_resource_requirements(improvements),
                "success_metrics": self._define_success_metrics(improvements),
            }

            logger.info("Security improvement prioritization completed", total_improvements=len(improvements))

            return improvement_plan

        except Exception as e:
            logger.error("Security improvement prioritization failed", error=str(e))
            raise

    async def generate_comprehensive_gap_analysis(self) -> Dict[str, Any]:
        """Generate comprehensive security gap analysis report.

        Returns:
            Dictionary containing complete gap analysis
        """
        logger.info("Generating comprehensive security gap analysis")

        try:
            # Perform all analysis components
            vulnerabilities = await self.identify_security_vulnerabilities()
            compliance = await self.assess_compliance_requirements()
            improvements = await self.prioritize_security_improvements()

            # Get additional context
            access_audit = await self.access_auditor.generate_comprehensive_report()
            monitoring_metrics = await self.monitoring_service.generate_dashboard_metrics()

            # Create comprehensive gap analysis
            gap_analysis = {
                "analysis_metadata": {
                    "generated_at": self.analysis_timestamp.isoformat(),
                    "analyzer_version": "1.0.0",
                    "scope": "comprehensive_security_gap_analysis",
                },
                "executive_summary": {
                    "overall_security_posture": self._calculate_security_grade(
                        vulnerabilities["risk_score"], compliance["overall_compliance_score"]
                    ),
                    "critical_findings": len(vulnerabilities["critical_vulnerabilities"]),
                    "compliance_score": compliance["overall_compliance_score"],
                    "immediate_actions_required": len(improvements["immediate_actions"]),
                    "estimated_remediation_timeline": improvements["estimated_timeline"],
                },
                "vulnerability_analysis": vulnerabilities,
                "compliance_assessment": compliance,
                "improvement_prioritization": improvements,
                "access_control_review": {
                    "summary": access_audit["executive_summary"],
                    "critical_violations": access_audit["access_matrix"]["summary"]["critical_issues"],
                },
                "security_monitoring_status": {
                    "active_threats": monitoring_metrics["active_threats"],
                    "security_score": monitoring_metrics["security_score"],
                    "monitoring_effectiveness": (
                        "operational" if monitoring_metrics["active_threats"] == 0 else "needs_attention"
                    ),
                },
                "recommendations": {
                    "immediate": improvements["immediate_actions"],
                    "strategic": self._generate_strategic_recommendations(vulnerabilities, compliance),
                    "architectural": self._generate_architectural_recommendations(),
                },
                "implementation_roadmap": self._create_implementation_roadmap(improvements),
                "success_metrics": improvements["success_metrics"],
            }

            logger.info("Comprehensive security gap analysis completed")

            return gap_analysis

        except Exception as e:
            logger.error("Comprehensive security gap analysis failed", error=str(e))
            raise

    # Private helper methods

    async def _analyze_access_control_vulnerabilities(self) -> Dict[str, Any]:
        """Analyze access control vulnerabilities."""
        access_audit = await self.access_auditor.analyze_rbac_system()

        vulnerabilities = []

        # Check for excessive admin users
        admin_percentage = access_audit.get("rbac_effectiveness", {}).get("user_activation_rate", 0) * 100
        if admin_percentage > 20:
            vulnerabilities.append(
                {
                    "id": "AC001",
                    "title": "Excessive Administrative Privileges",
                    "description": f"{admin_percentage:.1f}% of users have admin privileges",
                    "severity": "high",
                    "category": "access_control",
                    "remediation": "Review and reduce admin role assignments",
                }
            )

        return {
            "category": "access_control",
            "vulnerabilities": vulnerabilities,
            "risk_score": len([v for v in vulnerabilities if v["severity"] in ["critical", "high"]]) * 5,
        }

    async def _analyze_authentication_vulnerabilities(self) -> Dict[str, Any]:
        """Analyze authentication vulnerabilities."""
        auth_report = await self.audit_service.analyze_authentication_security()

        vulnerabilities = []

        # Check for MFA coverage
        critical_auth_issues = len([f for f in auth_report.findings if f["severity"] == "critical"])
        if critical_auth_issues > 0:
            vulnerabilities.append(
                {
                    "id": "AU001",
                    "title": "Critical Authentication Issues",
                    "description": f"{critical_auth_issues} critical authentication vulnerabilities found",
                    "severity": "critical",
                    "category": "authentication",
                    "remediation": "Address critical authentication issues immediately",
                }
            )

        return {"category": "authentication", "vulnerabilities": vulnerabilities, "risk_score": auth_report.risk_score}

    async def _analyze_cryptographic_vulnerabilities(self) -> Dict[str, Any]:
        """Analyze cryptographic vulnerabilities."""
        vulnerabilities = []

        # Check for encryption implementation
        vulnerabilities.append(
            {
                "id": "CR001",
                "title": "Field-Level Encryption Not Fully Implemented",
                "description": "Application-level encryption for sensitive data is not fully deployed",
                "severity": "medium",
                "category": "cryptography",
                "remediation": "Complete implementation of field-level encryption for PII",
            }
        )

        return {"category": "cryptography", "vulnerabilities": vulnerabilities, "risk_score": len(vulnerabilities) * 2}

    async def _analyze_configuration_vulnerabilities(self) -> Dict[str, Any]:
        """Analyze configuration vulnerabilities."""
        vulnerabilities = []

        # Check security configuration
        if self.settings.DEBUG:
            vulnerabilities.append(
                {
                    "id": "CF001",
                    "title": "Debug Mode Enabled",
                    "description": "Application is running in debug mode",
                    "severity": "medium",
                    "category": "configuration",
                    "remediation": "Disable debug mode in production",
                }
            )

        return {"category": "configuration", "vulnerabilities": vulnerabilities, "risk_score": len(vulnerabilities) * 3}

    async def _analyze_logging_vulnerabilities(self) -> Dict[str, Any]:
        """Analyze logging and monitoring vulnerabilities."""
        vulnerabilities = []

        # Basic logging assessment
        vulnerabilities.append(
            {
                "id": "LG001",
                "title": "Enhanced Security Monitoring Needed",
                "description": "Security monitoring capabilities can be enhanced",
                "severity": "low",
                "category": "logging",
                "remediation": "Implement additional security monitoring alerts",
            }
        )

        return {"category": "logging", "vulnerabilities": vulnerabilities, "risk_score": len(vulnerabilities) * 1}

    async def _assess_framework_compliance(self, framework_name: str, controls: Dict[str, Any]) -> Dict[str, Any]:
        """Assess compliance against a specific framework."""
        # Simplified compliance assessment
        gaps = []
        compliant_controls = 0
        total_controls = len(controls)

        for control_name, control_info in controls.items():
            # Basic compliance check (this would be more sophisticated in practice)
            is_compliant = self._check_control_compliance(framework_name, control_name, control_info)

            if is_compliant:
                compliant_controls += 1
            else:
                gaps.append(
                    {
                        "framework": framework_name,
                        "control": control_name,
                        "description": f"Non-compliance with {control_name}",
                        "impact": "medium",  # Would be calculated based on control weight
                        "category": control_info["category"],
                    }
                )

        compliance_percentage = (compliant_controls / total_controls * 100) if total_controls > 0 else 0

        return {
            "framework": framework_name,
            "compliance_percentage": compliance_percentage,
            "compliant_controls": compliant_controls,
            "total_controls": total_controls,
            "gaps": gaps,
            "status": "compliant" if compliance_percentage >= 80 else "non_compliant",
        }

    def _check_control_compliance(self, framework: str, control: str, control_info: Dict[str, Any]) -> bool:
        """Check if a specific control is compliant."""
        # Simplified compliance check - in practice this would be much more detailed
        category = control_info.get("category", "")

        # Basic compliance assumptions
        if category == "access_control":
            return True  # Assume RBAC is implemented
        elif category == "encryption":
            return False  # Field encryption not fully implemented
        elif category == "authentication":
            return True  # JWT auth is implemented
        elif category == "monitoring":
            return True  # Basic monitoring is implemented
        else:
            return True  # Default to compliant for other categories

    def _calculate_vulnerability_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        """Calculate overall vulnerability risk score."""
        total_score = 0
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "low")
            severity_info = self.gap_severity.get(severity, {"score": 1})
            if isinstance(severity_info, dict) and "score" in severity_info:
                score = severity_info["score"]
                if isinstance(score, int):
                    total_score += score
                else:
                    total_score += 1  # Default score
            else:
                total_score += 1  # Default score
        return total_score

    def _calculate_security_grade(self, vulnerability_score: int, compliance_score: float) -> str:
        """Calculate overall security grade."""
        # Weighted score: 60% compliance, 40% vulnerability
        overall_score = (compliance_score * 0.6) + ((100 - min(vulnerability_score, 50)) * 0.4)

        if overall_score >= 90:
            return "A"
        elif overall_score >= 80:
            return "B"
        elif overall_score >= 70:
            return "C"
        elif overall_score >= 60:
            return "D"
        else:
            return "F"

    async def _analyze_security_posture(self) -> Dict[str, Any]:
        """Analyze current security posture."""
        return {
            "current_maturity_level": "developing",
            "recommended_enhancements": [
                {
                    "title": "Implement Comprehensive Security Monitoring",
                    "description": "Deploy advanced threat detection and response capabilities",
                    "priority": "high",
                    "impact": "high",
                    "effort": "medium",
                    "timeline": "short_term",
                },
                {
                    "title": "Complete Field-Level Encryption",
                    "description": "Finish implementing encryption for all sensitive data fields",
                    "priority": "medium",
                    "impact": "medium",
                    "effort": "medium",
                    "timeline": "medium_term",
                },
            ],
        }

    def _estimate_remediation_effort(self, vulnerability: Dict[str, Any]) -> str:
        """Estimate effort required to remediate vulnerability."""
        severity = vulnerability.get("severity", "low")
        if severity == "critical":
            return "high"
        elif severity == "high":
            return "medium"
        else:
            return "low"

    def _estimate_compliance_effort(self, gap: Dict[str, Any]) -> str:
        """Estimate effort required to address compliance gap."""
        return "medium"  # Simplified estimation

    def _estimate_overall_timeline(self, improvements: List[Dict[str, Any]]) -> str:
        """Estimate overall implementation timeline."""
        critical_count = len([i for i in improvements if i["priority"] == "critical"])
        if critical_count > 0:
            return "3-6 months for critical issues, 12-18 months for complete remediation"
        else:
            return "6-12 months for complete implementation"

    def _estimate_resource_requirements(self, improvements: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Estimate resource requirements."""
        return {
            "personnel": "2-3 security engineers",
            "budget": "moderate investment required",
            "timeline": "phased implementation over 12-18 months",
            "external_support": "security consultation recommended for critical items",
        }

    def _define_success_metrics(self, improvements: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Define success metrics for improvements."""
        return [
            {"metric": "Vulnerability reduction", "target": "90% reduction in high/critical vulnerabilities"},
            {"metric": "Compliance score", "target": "Achieve 95%+ compliance across all frameworks"},
            {"metric": "Security incident response", "target": "Mean time to detection < 1 hour"},
            {"metric": "Access control effectiveness", "target": "100% role assignment validation"},
        ]

    async def _generate_compliance_recommendations(self, gaps: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Generate compliance recommendations."""
        recommendations = []

        gap_categories = set(gap.get("category", "general") for gap in gaps)

        for category in gap_categories:
            recommendations.append(
                {
                    "category": category,
                    "recommendation": f"Address {category} compliance gaps through targeted improvements",
                    "priority": "high" if len([g for g in gaps if g.get("category") == category]) > 2 else "medium",
                }
            )

        return recommendations

    def _generate_strategic_recommendations(
        self, vulnerabilities: Dict[str, Any], compliance: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Generate strategic security recommendations."""
        return [
            {
                "area": "Security Governance",
                "recommendation": "Establish formal security governance framework",
                "rationale": "Improve overall security posture coordination",
            },
            {
                "area": "Risk Management",
                "recommendation": "Implement continuous security risk assessment",
                "rationale": "Proactive identification and mitigation of security risks",
            },
            {
                "area": "Security Culture",
                "recommendation": "Enhance security awareness and training programs",
                "rationale": "Improve human element of security",
            },
        ]

    def _generate_architectural_recommendations(self) -> List[Dict[str, str]]:
        """Generate architectural security recommendations."""
        return [
            {
                "component": "API Security",
                "recommendation": "Implement API gateway with advanced security features",
                "benefit": "Centralized security policy enforcement",
            },
            {
                "component": "Data Protection",
                "recommendation": "Deploy data loss prevention (DLP) solutions",
                "benefit": "Prevent unauthorized data exfiltration",
            },
            {
                "component": "Infrastructure",
                "recommendation": "Implement zero-trust network architecture",
                "benefit": "Enhanced network security and access control",
            },
        ]

    def _create_implementation_roadmap(self, improvements: Dict[str, Any]) -> Dict[str, Any]:
        """Create implementation roadmap."""
        return {
            "phase_1": {
                "timeline": "0-3 months",
                "focus": "Critical vulnerabilities and immediate security improvements",
                "deliverables": improvements["immediate_actions"],
            },
            "phase_2": {
                "timeline": "3-9 months",
                "focus": "High-priority compliance gaps and security enhancements",
                "deliverables": improvements["short_term_goals"],
            },
            "phase_3": {
                "timeline": "9-18 months",
                "focus": "Comprehensive security program maturation",
                "deliverables": improvements["medium_term_objectives"],
            },
        }


async def main() -> None:
    """Main function for running the security gap analysis."""
    logger.info("Starting ViolentUTF API Security Gap Analysis")

    try:
        async with get_db() as session:
            analyzer = SecurityGapAnalyzer(session)

            # Generate comprehensive gap analysis
            gap_analysis = await analyzer.generate_comprehensive_gap_analysis()

            # Save analysis to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_gap_analysis_{timestamp}.json"

            with open(filename, "w") as f:
                json.dump(gap_analysis, f, indent=2, default=str)

            logger.info(f"Security gap analysis saved to {filename}")

            # Print summary
            print("\n=== ViolentUTF API Security Gap Analysis Summary ===")
            print(f"Overall Security Posture: {gap_analysis['executive_summary']['overall_security_posture']}")
            print(f"Critical Findings: {gap_analysis['executive_summary']['critical_findings']}")
            print(f"Compliance Score: {gap_analysis['executive_summary']['compliance_score']:.1f}%")
            print(f"Immediate Actions Required: {gap_analysis['executive_summary']['immediate_actions_required']}")
            print(f"Estimated Timeline: {gap_analysis['executive_summary']['estimated_remediation_timeline']}")
            print(f"\nDetailed analysis saved to: {filename}")

    except Exception as e:
        logger.error("Security gap analysis failed", error=str(e))
        raise


if __name__ == "__main__":
    asyncio.run(main())
