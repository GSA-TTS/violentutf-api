#!/usr/bin/env python3
"""Access Control Audit Script for ViolentUTF API - Issue #124.

This script provides comprehensive access control auditing capabilities including:
- RBAC system analysis
- API key usage pattern auditing
- OAuth scope and permission review
- MFA coverage assessment
- Access matrix generation with least privilege recommendations
"""

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import asyncpg
from sqlalchemy import and_, desc, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.core.config import get_settings
from app.db.session import get_db
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.models.mfa import MFADevice
from app.models.oauth import OAuthAccessToken, OAuthApplication, OAuthRefreshToken
from app.models.user import User
from app.models.user_role import UserRole
from audit_utils.logging import log_audit_event, setup_audit_logger

logger = setup_audit_logger(__name__)


class AccessControlAuditor:
    """Comprehensive access control audit system."""

    def __init__(self, session: Optional[AsyncSession] = None):
        """Initialize the auditor with database session."""
        self.session = session
        self.settings = get_settings()
        self.audit_timestamp = datetime.now(timezone.utc)

    async def analyze_rbac_system(self) -> Dict[str, Any]:
        """Analyze the Role-Based Access Control system comprehensively.

        Returns:
            Dictionary containing complete RBAC analysis
        """
        log_audit_event("rbac_analysis_start", module="access_audit", analysis_type="rbac")

        try:
            # Get all users with their roles
            if not self.session:
                raise ValueError("Database session is required")

            users_query = select(User).where(User.is_deleted == False)  # noqa: E712
            result = await self.session.execute(users_query)
            users = result.scalars().all()

            # Analyze role distribution
            role_distribution: Dict[str, int] = {}
            user_role_mappings: List[Dict[str, Any]] = []

            for user in users:
                for role in user.roles:
                    role_distribution[role] = role_distribution.get(role, 0) + 1
                    user_role_mappings.append(
                        {
                            "user_id": str(user.id),
                            "username": user.username,
                            "email": user.email,
                            "role": role,
                            "is_active": user.is_active,
                            "is_verified": user.is_verified,
                            "last_login": user.last_login_at.isoformat() if user.last_login_at else None,
                        }
                    )

            # UserRole relationships analysis would go here if needed in future

            # Analyze role hierarchy and permissions
            role_hierarchy = {
                "admin": {"inherits_from": ["tester", "viewer"], "level": 3},
                "tester": {"inherits_from": ["viewer"], "level": 2},
                "viewer": {"inherits_from": [], "level": 1},
            }

            # Calculate statistics
            total_users = len(users)
            active_users = len([u for u in users if u.is_active])
            verified_users = len([u for u in users if u.is_verified])

            analysis_result = {
                "audit_timestamp": self.audit_timestamp.isoformat(),
                "total_users": total_users,
                "active_users": active_users,
                "verified_users": verified_users,
                "role_distribution": role_distribution,
                "user_role_mappings": user_role_mappings,
                "role_hierarchy": role_hierarchy,
                "rbac_effectiveness": {
                    "role_coverage": len(role_distribution) / 3,  # 3 defined roles
                    "user_activation_rate": active_users / total_users if total_users > 0 else 0,
                    "verification_rate": verified_users / total_users if total_users > 0 else 0,
                },
                "recommendations": self._generate_rbac_recommendations(role_distribution, list(users)),
            }

            log_audit_event(
                "rbac_analysis_completed",
                module="access_audit",
                total_users=total_users,
                role_count=len(role_distribution),
                analysis_type="rbac",
            )

            return analysis_result

        except Exception as e:
            logger.error("RBAC analysis failed", error=str(e))
            raise

    async def audit_api_key_usage(self) -> Dict[str, Any]:
        """Audit API key usage patterns and security.

        Returns:
            Dictionary containing API key audit results
        """
        logger.info("Starting API key usage audit")

        try:
            # Get all API keys
            if not self.session:
                raise ValueError("Database session is required")

            api_keys_query = select(APIKey).where(APIKey.is_deleted == False)  # noqa: E712
            result = await self.session.execute(api_keys_query)
            api_keys = result.scalars().all()

            # Analyze usage patterns
            total_keys = len(api_keys)
            active_keys = len([k for k in api_keys if getattr(k, "is_active", False)])
            expired_keys = len([k for k in api_keys if k.expires_at and k.expires_at < self.audit_timestamp])

            # Get usage statistics from audit logs
            api_key_usage_query = select(AuditLog).where(
                and_(
                    AuditLog.action.like("api_key.%"), AuditLog.created_at >= self.audit_timestamp - timedelta(days=30)
                )
            )
            usage_result = await self.session.execute(api_key_usage_query)
            usage_logs = usage_result.scalars().all()

            # Analyze usage patterns
            usage_patterns: Dict[str, Dict[str, Any]] = {}
            for log in usage_logs:
                key_id = log.resource_id
                if key_id:
                    if key_id not in usage_patterns:
                        usage_patterns[key_id] = {"count": 0, "last_used": None, "actions": []}
                    usage_patterns[key_id]["count"] += 1
                    usage_patterns[key_id]["actions"].append(log.action)
                    if not usage_patterns[key_id]["last_used"] or log.created_at > usage_patterns[key_id]["last_used"]:
                        usage_patterns[key_id]["last_used"] = log.created_at

            # Identify security violations
            security_violations = []
            for api_key in api_keys:
                key_id = str(api_key.id)

                # Check for unused keys
                if key_id not in usage_patterns:
                    security_violations.append(
                        {
                            "type": "unused_api_key",
                            "key_id": key_id,
                            "user_id": str(api_key.user_id) if api_key.user_id else None,
                            "created_at": api_key.created_at.isoformat() if api_key.created_at else None,
                            "severity": "medium",
                        }
                    )

                # Check for keys without expiration
                if not api_key.expires_at:
                    security_violations.append(
                        {
                            "type": "no_expiration",
                            "key_id": key_id,
                            "user_id": str(api_key.user_id) if api_key.user_id else None,
                            "severity": "high",
                        }
                    )

            audit_result = {
                "audit_timestamp": self.audit_timestamp.isoformat(),
                "total_api_keys": total_keys,
                "active_keys": active_keys,
                "expired_keys": expired_keys,
                "usage_patterns": {
                    "keys_used_last_30_days": len(usage_patterns),
                    "total_api_calls": sum(p["count"] for p in usage_patterns.values()),
                    "most_active_keys": sorted(
                        [(k, v["count"]) for k, v in usage_patterns.items()], key=lambda x: x[1], reverse=True
                    )[:10],
                },
                "security_violations": security_violations,
                "recommendations": self._generate_api_key_recommendations(list(api_keys), usage_patterns),
            }

            logger.info("API key audit completed", total_keys=total_keys, violations=len(security_violations))

            return audit_result

        except Exception as e:
            logger.error("API key audit failed", error=str(e))
            raise

    async def review_oauth_scopes(self) -> Dict[str, Any]:
        """Review OAuth application scopes and permissions.

        Returns:
            Dictionary containing OAuth scope analysis
        """
        logger.info("Starting OAuth scope review")

        try:
            # Get OAuth applications
            if not self.session:
                raise ValueError("Database session is required")

            apps_query = select(OAuthApplication).where(OAuthApplication.is_deleted == False)  # noqa: E712
            apps_result = await self.session.execute(apps_query)
            applications = apps_result.scalars().all()

            # Get access tokens
            tokens_query = select(OAuthAccessToken)
            tokens_result = await self.session.execute(tokens_query)
            access_tokens = tokens_result.scalars().all()

            # Analyze scope usage
            scope_analysis: Dict[str, Dict[str, Any]] = {}
            for app in applications:
                app_id = str(app.id)
                scopes = getattr(app, "scope", "").split() if getattr(app, "scope", "") else []

                scope_analysis[app_id] = {
                    "application_name": app.name,
                    "client_id": app.client_id,
                    "scopes": scopes,
                    "is_confidential": app.is_confidential,
                    "active_tokens": 0,
                    "users": set(),
                }

            # Count active tokens and users per application
            for token in access_tokens:
                if token.expires_at and token.expires_at > self.audit_timestamp:
                    app_id = str(token.application_id)
                    if app_id in scope_analysis:
                        scope_analysis[app_id]["active_tokens"] += 1
                        if token.user_id:
                            scope_analysis[app_id]["users"].add(str(token.user_id))

            # Convert sets to counts for serialization
            for app_data in scope_analysis.values():
                app_data["unique_users"] = len(app_data["users"])
                del app_data["users"]

            # Identify excessive permissions
            excessive_permissions = []
            for app_id, data in scope_analysis.items():
                if "admin" in data["scopes"] and data["active_tokens"] == 0:
                    excessive_permissions.append(
                        {
                            "application_id": app_id,
                            "application_name": data["application_name"],
                            "issue": "admin_scope_unused",
                            "severity": "high",
                        }
                    )

                if len(data["scopes"]) > 5:  # Arbitrary threshold
                    excessive_permissions.append(
                        {
                            "application_id": app_id,
                            "application_name": data["application_name"],
                            "issue": "too_many_scopes",
                            "scope_count": len(data["scopes"]),
                            "severity": "medium",
                        }
                    )

            review_result = {
                "audit_timestamp": self.audit_timestamp.isoformat(),
                "total_applications": len(applications),
                "active_applications": len([a for a in applications if a.is_active]),
                "applications": scope_analysis,
                "scope_mappings": {
                    "viewer": ["read:basic", "read:profile"],
                    "tester": ["read:basic", "read:profile", "write:test", "read:test"],
                    "admin": ["read:*", "write:*", "delete:*", "admin:*"],
                },
                "permission_grants": {
                    "total_active_tokens": len(
                        [t for t in access_tokens if t.expires_at and t.expires_at > self.audit_timestamp]
                    ),
                    "expired_tokens": len(
                        [t for t in access_tokens if t.expires_at and t.expires_at <= self.audit_timestamp]
                    ),
                },
                "excessive_permissions": excessive_permissions,
                "recommendations": self._generate_oauth_recommendations(list(applications), excessive_permissions),
            }

            logger.info(
                "OAuth scope review completed",
                applications=len(applications),
                excessive_perms=len(excessive_permissions),
            )

            return review_result

        except Exception as e:
            logger.error("OAuth scope review failed", error=str(e))
            raise

    async def assess_mfa_coverage(self) -> Dict[str, Any]:
        """Assess Multi-Factor Authentication coverage and compliance.

        Returns:
            Dictionary containing MFA assessment results
        """
        logger.info("Starting MFA coverage assessment")

        try:
            # Get all users
            if not self.session:
                raise ValueError("Database session is required")

            users_query = select(User).where(User.is_deleted == False)  # noqa: E712
            users_result = await self.session.execute(users_query)
            users = users_result.scalars().all()

            # Get MFA devices
            mfa_devices_query = select(MFADevice).where(MFADevice.is_deleted == False)  # noqa: E712
            mfa_result = await self.session.execute(mfa_devices_query)
            mfa_devices = mfa_result.scalars().all()

            # Analyze MFA coverage
            total_users = len(users)
            users_with_mfa: Set[str] = set()
            mfa_by_type: Dict[str, int] = {}

            for device in mfa_devices:
                if device.is_active:
                    users_with_mfa.add(str(device.user_id))
                    device_type = getattr(device, "device_type", "unknown")
                    mfa_by_type[device_type] = mfa_by_type.get(device_type, 0) + 1

            mfa_enabled_count = len(users_with_mfa)
            coverage_percentage = (mfa_enabled_count / total_users * 100) if total_users > 0 else 0

            # Identify users without MFA by role
            users_without_mfa: Dict[str, List[Dict[str, Any]]] = {"admin": [], "tester": [], "viewer": []}

            for user in users:
                user_id = str(user.id)
                if user_id not in users_with_mfa and user.is_active:
                    for role in user.roles:
                        if role in users_without_mfa:
                            users_without_mfa[role].append(
                                {
                                    "user_id": user_id,
                                    "username": user.username,
                                    "email": user.email,
                                    "last_login": user.last_login_at.isoformat() if user.last_login_at else None,
                                }
                            )

            # Compliance assessment
            compliance_requirements = {
                "admin_mfa_required": len(users_without_mfa["admin"]) == 0,
                "tester_mfa_recommended": len(users_without_mfa["tester"])
                < len([u for u in users if "tester" in u.roles]) * 0.2,
                "overall_coverage_target": coverage_percentage >= 80,
            }

            compliance_status = "compliant" if all(compliance_requirements.values()) else "non_compliant"

            assessment_result = {
                "audit_timestamp": self.audit_timestamp.isoformat(),
                "total_users": total_users,
                "mfa_enabled_users": mfa_enabled_count,
                "coverage_percentage": round(coverage_percentage, 2),
                "mfa_device_types": mfa_by_type,
                "users_without_mfa": users_without_mfa,
                "compliance_requirements": compliance_requirements,
                "compliance_status": compliance_status,
                "recommendations": self._generate_mfa_recommendations(users_without_mfa, coverage_percentage),
            }

            logger.info("MFA assessment completed", coverage=f"{coverage_percentage:.1f}%", status=compliance_status)

            return assessment_result

        except Exception as e:
            logger.error("MFA assessment failed", error=str(e))
            raise

    async def generate_access_matrix(self) -> Dict[str, Any]:
        """Generate comprehensive access control matrix with least privilege analysis.

        Returns:
            Dictionary containing access matrix and recommendations
        """
        logger.info("Generating access control matrix")

        try:
            # Get comprehensive user and permission data
            rbac_analysis = await self.analyze_rbac_system()
            api_audit = await self.audit_api_key_usage()
            oauth_review = await self.review_oauth_scopes()
            mfa_assessment = await self.assess_mfa_coverage()

            # Build access matrix
            access_matrix = {
                "roles": {
                    "viewer": {
                        "permissions": ["read:basic", "read:profile"],
                        "api_access": True,
                        "oauth_scopes": ["read:basic"],
                        "mfa_required": False,
                    },
                    "tester": {
                        "permissions": ["read:basic", "read:profile", "write:test", "read:test"],
                        "api_access": True,
                        "oauth_scopes": ["read:basic", "write:test"],
                        "mfa_required": True,
                    },
                    "admin": {
                        "permissions": ["read:*", "write:*", "delete:*", "admin:*"],
                        "api_access": True,
                        "oauth_scopes": ["read:*", "write:*", "admin:*"],
                        "mfa_required": True,
                    },
                },
                "user_permissions": rbac_analysis["user_role_mappings"],
                "api_key_access": api_audit["usage_patterns"],
                "oauth_permissions": oauth_review["applications"],
            }

            # Analyze violations and generate recommendations
            violations = []

            # Check for privilege violations
            for user_mapping in rbac_analysis["user_role_mappings"]:
                if "admin" in user_mapping["role"]:
                    user_id = user_mapping["user_id"]
                    if user_id not in [str(u["user_id"]) for u in mfa_assessment["users_without_mfa"]["admin"]]:
                        # Admin without MFA
                        violations.append({"type": "admin_without_mfa", "user_id": user_id, "severity": "critical"})

            # Least privilege analysis
            least_privilege_analysis: Dict[str, List[Dict[str, Any]]] = {
                "over_privileged_users": [],
                "under_privileged_users": [],
                "unused_permissions": [],
                "excessive_api_access": [],
            }

            # Identify over-privileged users (those with admin role but low activity)
            for user_mapping in rbac_analysis["user_role_mappings"]:
                if "admin" in user_mapping["role"] and not user_mapping["last_login"]:
                    least_privilege_analysis["over_privileged_users"].append(
                        {
                            "user_id": user_mapping["user_id"],
                            "username": user_mapping["username"],
                            "issue": "admin_role_no_login",
                        }
                    )

            matrix_result = {
                "audit_timestamp": self.audit_timestamp.isoformat(),
                "matrix": access_matrix,
                "violations": violations,
                "least_privilege_analysis": least_privilege_analysis,
                "recommendations": self._generate_access_matrix_recommendations(violations, least_privilege_analysis),
                "summary": {
                    "total_violations": len(violations),
                    "critical_issues": len([v for v in violations if v.get("severity") == "critical"]),
                    "rbac_effectiveness": rbac_analysis["rbac_effectiveness"],
                    "mfa_compliance": mfa_assessment["compliance_status"],
                },
            }

            logger.info(
                "Access matrix generated",
                violations=len(violations),
                critical=len([v for v in violations if v.get("severity") == "critical"]),
            )

            return matrix_result

        except Exception as e:
            logger.error("Access matrix generation failed", error=str(e))
            raise

    def _generate_rbac_recommendations(
        self, role_distribution: Dict[str, int], users: List[User]
    ) -> List[Dict[str, str]]:
        """Generate RBAC system recommendations."""
        recommendations = []

        # Check role distribution
        total_users = len(users)
        admin_percentage = (role_distribution.get("admin", 0) / total_users * 100) if total_users > 0 else 0

        if admin_percentage > 20:
            recommendations.append(
                {
                    "type": "role_distribution",
                    "priority": "high",
                    "issue": f"Too many admin users ({admin_percentage:.1f}%)",
                    "action": "Review admin role assignments and demote users where appropriate",
                }
            )

        # Check for inactive users with privileges
        for user in users:
            if not user.is_active and "admin" in user.roles:
                recommendations.append(
                    {
                        "type": "inactive_privileged_user",
                        "priority": "critical",
                        "issue": f"Inactive user {user.username} has admin privileges",
                        "action": "Remove admin role or reactivate user",
                    }
                )

        return recommendations

    def _generate_api_key_recommendations(
        self, api_keys: List[APIKey], usage_patterns: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Generate API key security recommendations."""
        recommendations = []

        unused_keys = len(api_keys) - len(usage_patterns)
        if unused_keys > 0:
            recommendations.append(
                {
                    "type": "unused_api_keys",
                    "priority": "medium",
                    "issue": f"{unused_keys} API keys have not been used in 30 days",
                    "action": "Review and revoke unused API keys",
                }
            )

        # Check for keys without expiration
        no_expiry_count = len([k for k in api_keys if not k.expires_at])
        if no_expiry_count > 0:
            recommendations.append(
                {
                    "type": "api_key_expiration",
                    "priority": "high",
                    "issue": f"{no_expiry_count} API keys do not have expiration dates",
                    "action": "Set expiration dates for all API keys",
                }
            )

        return recommendations

    def _generate_oauth_recommendations(
        self, applications: List[OAuthApplication], excessive_permissions: List[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        """Generate OAuth security recommendations."""
        recommendations = []

        if excessive_permissions:
            recommendations.append(
                {
                    "type": "oauth_permissions",
                    "priority": "high",
                    "issue": f"{len(excessive_permissions)} applications have excessive permissions",
                    "action": "Review and reduce OAuth application scopes",
                }
            )

        # Check for public applications with sensitive scopes
        for app in applications:
            app_scope = getattr(app, "scope", "")
            if not app.is_confidential and app_scope and "admin" in app_scope:
                recommendations.append(
                    {
                        "type": "public_app_admin_scope",
                        "priority": "critical",
                        "issue": f"Public application {app.name} has admin scope",
                        "action": "Make application confidential or remove admin scope",
                    }
                )

        return recommendations

    def _generate_mfa_recommendations(
        self, users_without_mfa: Dict[str, List[Dict[str, Any]]], coverage_percentage: float
    ) -> List[Dict[str, str]]:
        """Generate MFA compliance recommendations."""
        recommendations = []

        if users_without_mfa["admin"]:
            recommendations.append(
                {
                    "type": "admin_mfa_required",
                    "priority": "critical",
                    "issue": f"{len(users_without_mfa['admin'])} admin users do not have MFA enabled",
                    "action": "Require MFA for all admin users immediately",
                }
            )

        if coverage_percentage < 80:
            recommendations.append(
                {
                    "type": "mfa_coverage",
                    "priority": "high",
                    "issue": f"Overall MFA coverage is {coverage_percentage:.1f}% (target: 80%)",
                    "action": "Implement MFA enrollment campaign for all users",
                }
            )

        return recommendations

    def _generate_access_matrix_recommendations(
        self, violations: List[Dict[str, Any]], least_privilege_analysis: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Generate access matrix recommendations."""
        recommendations = []

        critical_violations = len([v for v in violations if v.get("severity") == "critical"])
        if critical_violations > 0:
            recommendations.append(
                {
                    "type": "critical_violations",
                    "priority": "critical",
                    "issue": f"{critical_violations} critical access control violations found",
                    "action": "Address critical violations immediately",
                }
            )

        over_privileged = len(least_privilege_analysis["over_privileged_users"])
        if over_privileged > 0:
            recommendations.append(
                {
                    "type": "least_privilege",
                    "priority": "high",
                    "issue": f"{over_privileged} users may be over-privileged",
                    "action": "Review and reduce user privileges following least privilege principle",
                }
            )

        return recommendations

    async def generate_comprehensive_report(self) -> Dict[str, Any]:
        """Generate a comprehensive access control audit report."""
        logger.info("Generating comprehensive access control audit report")

        try:
            # Perform all audits
            rbac_analysis = await self.analyze_rbac_system()
            api_audit = await self.audit_api_key_usage()
            oauth_review = await self.review_oauth_scopes()
            mfa_assessment = await self.assess_mfa_coverage()
            access_matrix = await self.generate_access_matrix()

            # Compile comprehensive report
            report = {
                "report_metadata": {
                    "generated_at": self.audit_timestamp.isoformat(),
                    "auditor_version": "1.0.0",
                    "scope": "comprehensive_access_control",
                },
                "executive_summary": {
                    "total_users": rbac_analysis["total_users"],
                    "mfa_coverage": f"{mfa_assessment['coverage_percentage']:.1f}%",
                    "compliance_status": mfa_assessment["compliance_status"],
                    "critical_violations": len(
                        [v for v in access_matrix["violations"] if v.get("severity") == "critical"]
                    ),
                    "total_recommendations": len(access_matrix["recommendations"]),
                },
                "rbac_analysis": rbac_analysis,
                "api_key_audit": api_audit,
                "oauth_review": oauth_review,
                "mfa_assessment": mfa_assessment,
                "access_matrix": access_matrix,
                "recommendations": {
                    "immediate_actions": [
                        r for r in access_matrix["recommendations"] if r.get("priority") == "critical"
                    ],
                    "high_priority": [r for r in access_matrix["recommendations"] if r.get("priority") == "high"],
                    "medium_priority": [r for r in access_matrix["recommendations"] if r.get("priority") == "medium"],
                },
            }

            logger.info("Comprehensive audit report generated successfully")
            return report

        except Exception as e:
            logger.error("Comprehensive report generation failed", error=str(e))
            raise


async def main() -> None:
    """Main function for running the access control audit."""
    logger.info("Starting ViolentUTF API Access Control Audit")

    try:
        # Get database session
        async with get_db() as session:
            auditor = AccessControlAuditor(session)

            # Generate comprehensive report
            report = await auditor.generate_comprehensive_report()

            # Save report to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"access_control_audit_{timestamp}.json"

            with open(filename, "w") as f:
                json.dump(report, f, indent=2, default=str)

            logger.info(f"Audit report saved to {filename}")

            # Print summary
            print("\n=== ViolentUTF API Access Control Audit Summary ===")
            print(f"Total Users: {report['executive_summary']['total_users']}")
            print(f"MFA Coverage: {report['executive_summary']['mfa_coverage']}")
            print(f"Compliance Status: {report['executive_summary']['compliance_status']}")
            print(f"Critical Violations: {report['executive_summary']['critical_violations']}")
            print(f"Total Recommendations: {report['executive_summary']['total_recommendations']}")
            print(f"\nDetailed report saved to: {filename}")

    except Exception as e:
        logger.error("Access control audit failed", error=str(e))
        raise


if __name__ == "__main__":
    asyncio.run(main())
