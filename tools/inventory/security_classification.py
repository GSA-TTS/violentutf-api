"""Security Classification Framework for ViolentUTF API Data Assets.

This module provides automated security classification capabilities based on:
- Data sensitivity patterns
- Risk factor analysis
- Regulatory compliance requirements
- Access pattern evaluation
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog

logger = structlog.get_logger(__name__)


class SecurityClassification(Enum):
    """Security classification levels for data assets."""

    CRITICAL = "critical"
    IMPORTANT = "important"
    STANDARD = "standard"
    DEVELOPMENT = "development"


@dataclass
class ClassificationRule:
    """Rule for automated asset classification."""

    name: str
    description: str
    classification: SecurityClassification
    patterns: List[str]
    risk_factors: List[str]
    priority: int = 50  # Higher priority rules are evaluated first
    conditions: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ClassificationResult:
    """Result of security classification analysis."""

    asset_id: str
    asset_type: str
    classification: SecurityClassification
    confidence_score: float
    matched_rules: List[str]
    risk_factors: List[str]
    recommendations: List[str]
    compliance_tags: List[str]
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat() + "Z")


class SecurityClassificationEngine:
    """Automated security classification engine for data assets."""

    def __init__(self):
        """Initialize the classification engine with predefined rules."""
        self.rules = self._initialize_classification_rules()
        self.sensitivity_patterns = self._initialize_sensitivity_patterns()
        self.compliance_mappings = self._initialize_compliance_mappings()

    def _initialize_classification_rules(self) -> List[ClassificationRule]:
        """Initialize the comprehensive set of classification rules."""
        rules = [
            # CRITICAL Classification Rules
            ClassificationRule(
                name="authentication_credentials",
                description="Authentication credentials and API keys",
                classification=SecurityClassification.CRITICAL,
                patterns=[
                    r"api_key",
                    r"password",
                    r"secret",
                    r"token",
                    r"credential",
                    r"auth",
                    r"oauth",
                    r"jwt",
                    r"key_hash",
                    r"private_key",
                ],
                risk_factors=[
                    "authentication_bypass",
                    "external_access",
                    "high_privilege",
                    "system_compromise",
                    "data_breach",
                ],
                priority=90,
                conditions={"requires_encryption": True, "requires_rotation": True},
            ),
            ClassificationRule(
                name="personal_identifiable_information",
                description="Personal Identifiable Information (PII)",
                classification=SecurityClassification.CRITICAL,
                patterns=[
                    r"email",
                    r"phone",
                    r"ssn",
                    r"social_security",
                    r"address",
                    r"first_name",
                    r"last_name",
                    r"user",
                    r"profile",
                    r"personal",
                ],
                risk_factors=[
                    "privacy_violation",
                    "gdpr_compliance",
                    "ccpa_compliance",
                    "identity_theft",
                    "regulatory_violation",
                ],
                priority=85,
                conditions={"requires_encryption": True, "data_retention_policy": True},
            ),
            ClassificationRule(
                name="financial_data",
                description="Financial and payment information",
                classification=SecurityClassification.CRITICAL,
                patterns=[
                    r"payment",
                    r"credit_card",
                    r"bank",
                    r"financial",
                    r"billing",
                    r"transaction",
                    r"invoice",
                    r"price",
                    r"cost",
                ],
                risk_factors=[
                    "financial_fraud",
                    "pci_compliance",
                    "monetary_loss",
                    "regulatory_violation",
                    "financial_liability",
                ],
                priority=88,
                conditions={"requires_encryption": True, "pci_compliance": True},
            ),
            # IMPORTANT Classification Rules
            ClassificationRule(
                name="audit_security_logs",
                description="Audit logs and security monitoring data",
                classification=SecurityClassification.IMPORTANT,
                patterns=[
                    r"audit",
                    r"log",
                    r"security",
                    r"event",
                    r"monitoring",
                    r"alert",
                    r"incident",
                    r"violation",
                    r"access_log",
                ],
                risk_factors=[
                    "compliance_requirement",
                    "forensic_evidence",
                    "security_monitoring",
                    "incident_response",
                    "regulatory_reporting",
                ],
                priority=75,
                conditions={"retention_required": True, "immutable_logs": True},
            ),
            ClassificationRule(
                name="system_configuration",
                description="System configuration and operational data",
                classification=SecurityClassification.IMPORTANT,
                patterns=[
                    r"config",
                    r"settings",
                    r"parameter",
                    r"policy",
                    r"rule",
                    r"permission",
                    r"role",
                    r"scope",
                    r"template",
                ],
                risk_factors=[
                    "system_integrity",
                    "operational_disruption",
                    "privilege_escalation",
                    "configuration_drift",
                    "security_misconfiguration",
                ],
                priority=70,
                conditions={"change_tracking": True, "approval_required": True},
            ),
            ClassificationRule(
                name="business_intelligence",
                description="Business intelligence and analytics data",
                classification=SecurityClassification.IMPORTANT,
                patterns=[
                    r"analytics",
                    r"report",
                    r"metric",
                    r"dashboard",
                    r"kpi",
                    r"business",
                    r"intelligence",
                    r"insight",
                    r"summary",
                ],
                risk_factors=[
                    "competitive_advantage",
                    "business_strategy",
                    "intellectual_property",
                    "market_sensitivity",
                    "strategic_planning",
                ],
                priority=65,
                conditions={"access_control": True, "data_governance": True},
            ),
            # STANDARD Classification Rules
            ClassificationRule(
                name="application_data",
                description="Standard application operational data",
                classification=SecurityClassification.STANDARD,
                patterns=[
                    r"session",
                    r"cache",
                    r"temp",
                    r"queue",
                    r"job",
                    r"task",
                    r"workflow",
                    r"process",
                    r"request",
                    r"response",
                ],
                risk_factors=[
                    "availability_impact",
                    "performance_degradation",
                    "service_disruption",
                    "operational_efficiency",
                    "user_experience",
                ],
                priority=50,
                conditions={"backup_required": True, "monitoring": True},
            ),
            ClassificationRule(
                name="reference_data",
                description="Reference and lookup data",
                classification=SecurityClassification.STANDARD,
                patterns=[
                    r"lookup",
                    r"reference",
                    r"code",
                    r"type",
                    r"category",
                    r"status",
                    r"enum",
                    r"constant",
                    r"master",
                ],
                risk_factors=[
                    "data_consistency",
                    "referential_integrity",
                    "business_logic",
                    "application_functionality",
                    "data_quality",
                ],
                priority=45,
                conditions={"version_control": True, "data_validation": True},
            ),
            # DEVELOPMENT Classification Rules
            ClassificationRule(
                name="test_development_data",
                description="Test and development environment data",
                classification=SecurityClassification.DEVELOPMENT,
                patterns=[
                    r"test",
                    r"dev",
                    r"debug",
                    r"sample",
                    r"mock",
                    r"fixture",
                    r"prototype",
                    r"sandbox",
                    r"staging",
                    r"demo",
                ],
                risk_factors=[
                    "data_exposure",
                    "environment_confusion",
                    "test_data_leakage",
                    "development_security",
                    "staging_vulnerability",
                ],
                priority=25,
                conditions={"data_anonymization": True, "environment_isolation": True},
            ),
            ClassificationRule(
                name="temporary_data",
                description="Temporary and disposable data",
                classification=SecurityClassification.DEVELOPMENT,
                patterns=[
                    r"tmp",
                    r"temporary",
                    r"scratch",
                    r"working",
                    r"draft",
                    r"preview",
                    r"snapshot",
                    r"backup",
                    r"archive",
                ],
                risk_factors=[
                    "data_leakage",
                    "temporary_exposure",
                    "cleanup_failure",
                    "storage_overflow",
                    "retention_violation",
                ],
                priority=20,
                conditions={"automatic_cleanup": True, "access_restriction": True},
            ),
        ]

        # Sort rules by priority (higher priority first)
        return sorted(rules, key=lambda r: r.priority, reverse=True)

    def _initialize_sensitivity_patterns(self) -> Dict[str, List[str]]:
        """Initialize patterns for sensitive data detection."""
        return {
            "high_sensitivity": [
                r"password",
                r"secret",
                r"private_key",
                r"api_key",
                r"token",
                r"ssn",
                r"social_security",
                r"credit_card",
                r"bank_account",
                r"medical",
                r"health",
                r"biometric",
                r"genetic",
            ],
            "medium_sensitivity": [
                r"email",
                r"phone",
                r"address",
                r"name",
                r"user_id",
                r"session",
                r"cookie",
                r"preference",
                r"profile",
                r"financial",
                r"payment",
                r"billing",
                r"invoice",
            ],
            "low_sensitivity": [
                r"log",
                r"cache",
                r"temp",
                r"config",
                r"setting",
                r"status",
                r"type",
                r"category",
                r"reference",
                r"lookup",
                r"code",
                r"enum",
                r"constant",
            ],
        }

    def _initialize_compliance_mappings(self) -> Dict[str, List[str]]:
        """Initialize compliance framework mappings."""
        return {
            "GDPR": [
                "personal_data",
                "special_category_data",
                "pseudonymization",
                "data_portability",
                "right_to_erasure",
                "data_protection_impact",
            ],
            "CCPA": [
                "personal_information",
                "sensitive_personal_information",
                "sale_of_personal_information",
                "right_to_know",
                "right_to_delete",
            ],
            "HIPAA": [
                "protected_health_information",
                "medical_records",
                "health_data",
                "patient_information",
                "healthcare_data",
            ],
            "PCI_DSS": [
                "cardholder_data",
                "sensitive_authentication_data",
                "payment_card_information",
                "financial_transaction_data",
            ],
            "SOX": ["financial_records", "accounting_data", "audit_trail", "internal_controls", "financial_reporting"],
            "ISO_27001": [
                "information_assets",
                "risk_assessment",
                "security_controls",
                "incident_management",
                "access_control",
            ],
        }

    def classify_asset(
        self, asset_id: str, asset_type: str, asset_data: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> ClassificationResult:
        """
        Classify a single data asset.

        Args:
            asset_id: Unique identifier for the asset
            asset_type: Type of asset (table, repository, endpoint, etc.)
            asset_data: Asset metadata and properties
            context: Additional context for classification

        Returns:
            ClassificationResult with classification and analysis
        """
        context = context or {}

        # Extract text content for pattern matching
        text_content = self._extract_text_content(asset_data)

        # Evaluate classification rules
        matched_rules = []
        risk_factors = []
        classification_scores = {cls: 0.0 for cls in SecurityClassification}

        for rule in self.rules:
            rule_matches, rule_score = self._evaluate_rule(rule, text_content, asset_data, context)
            if rule_matches:
                matched_rules.append(rule.name)
                risk_factors.extend(rule.risk_factors)
                classification_scores[rule.classification] += rule_score

        # Determine final classification
        final_classification = max(classification_scores.keys(), key=lambda k: classification_scores[k])
        confidence_score = min(classification_scores[final_classification], 1.0)

        # Generate recommendations
        recommendations = self._generate_recommendations(final_classification, matched_rules, risk_factors)

        # Map compliance requirements
        compliance_tags = self._map_compliance_requirements(text_content, risk_factors)

        # Remove duplicate risk factors
        risk_factors = list(set(risk_factors))

        return ClassificationResult(
            asset_id=asset_id,
            asset_type=asset_type,
            classification=final_classification,
            confidence_score=confidence_score,
            matched_rules=matched_rules,
            risk_factors=risk_factors,
            recommendations=recommendations,
            compliance_tags=compliance_tags,
        )

    def classify_inventory(self, inventory_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify all assets in a comprehensive inventory.

        Args:
            inventory_data: Complete inventory data structure

        Returns:
            Enhanced inventory with security classifications
        """
        classified_inventory = inventory_data.copy()
        classification_summary = {
            "total_assets": 0,
            "classifications": {cls.value: 0 for cls in SecurityClassification},
            "high_risk_assets": [],
            "compliance_requirements": set(),
            "classification_timestamp": datetime.now().isoformat() + "Z",
        }

        # Classify physical stores
        if "physical_stores" in inventory_data:
            for store_id, store_data in inventory_data["physical_stores"].items():
                result = self.classify_asset(store_id, "physical_store", store_data)
                classified_inventory["physical_stores"][store_id]["security_classification"] = {
                    "level": result.classification.value,
                    "confidence": result.confidence_score,
                    "risk_factors": result.risk_factors,
                    "recommendations": result.recommendations,
                    "compliance_tags": result.compliance_tags,
                }
                classification_summary["classifications"][result.classification.value] += 1
                classification_summary["total_assets"] += 1
                classification_summary["compliance_requirements"].update(result.compliance_tags)

                if result.classification in [SecurityClassification.CRITICAL, SecurityClassification.IMPORTANT]:
                    classification_summary["high_risk_assets"].append(
                        {
                            "asset_id": store_id,
                            "type": "physical_store",
                            "classification": result.classification.value,
                            "risk_score": result.confidence_score,
                        }
                    )

        # Classify database tables
        if "logical_assets" in inventory_data and "database_schema" in inventory_data["logical_assets"]:
            schema_data = inventory_data["logical_assets"]["database_schema"]
            if "tables" in schema_data:
                for table in schema_data["tables"]:
                    table_name = table.get("name", "unknown")
                    result = self.classify_asset(table_name, "database_table", table)
                    table["security_classification"] = {
                        "level": result.classification.value,
                        "confidence": result.confidence_score,
                        "risk_factors": result.risk_factors,
                        "recommendations": result.recommendations,
                        "compliance_tags": result.compliance_tags,
                    }
                    classification_summary["classifications"][result.classification.value] += 1
                    classification_summary["total_assets"] += 1
                    classification_summary["compliance_requirements"].update(result.compliance_tags)

                    if result.classification in [SecurityClassification.CRITICAL, SecurityClassification.IMPORTANT]:
                        classification_summary["high_risk_assets"].append(
                            {
                                "asset_id": table_name,
                                "type": "database_table",
                                "classification": result.classification.value,
                                "risk_score": result.confidence_score,
                            }
                        )

        # Classify repository assets
        if "repository_analysis" in inventory_data:
            repos_data = inventory_data["repository_analysis"]
            if "repositories" in repos_data:
                for repo in repos_data["repositories"]:
                    repo_name = repo.get("repository_name", "unknown")
                    result = self.classify_asset(repo_name, "repository", repo)
                    repo["security_classification"] = {
                        "level": result.classification.value,
                        "confidence": result.confidence_score,
                        "risk_factors": result.risk_factors,
                        "recommendations": result.recommendations,
                        "compliance_tags": result.compliance_tags,
                    }
                    classification_summary["classifications"][result.classification.value] += 1
                    classification_summary["total_assets"] += 1
                    classification_summary["compliance_requirements"].update(result.compliance_tags)

                    if result.classification in [SecurityClassification.CRITICAL, SecurityClassification.IMPORTANT]:
                        classification_summary["high_risk_assets"].append(
                            {
                                "asset_id": repo_name,
                                "type": "repository",
                                "classification": result.classification.value,
                                "risk_score": result.confidence_score,
                            }
                        )

        # Convert compliance requirements set to list
        classification_summary["compliance_requirements"] = list(classification_summary["compliance_requirements"])

        # Add classification summary to inventory
        classified_inventory["security_classification_summary"] = classification_summary

        logger.info(
            "Completed security classification",
            total_assets=classification_summary["total_assets"],
            critical_assets=classification_summary["classifications"]["critical"],
            important_assets=classification_summary["classifications"]["important"],
            high_risk_count=len(classification_summary["high_risk_assets"]),
        )

        return classified_inventory

    def _extract_text_content(self, asset_data: Dict[str, Any]) -> str:
        """Extract all text content from asset data for pattern matching."""
        text_parts = []

        def extract_text_recursive(obj, depth=0):
            if depth > 5:  # Prevent infinite recursion
                return

            if isinstance(obj, str):
                text_parts.append(obj.lower())
            elif isinstance(obj, dict):
                for key, value in obj.items():
                    text_parts.append(str(key).lower())
                    extract_text_recursive(value, depth + 1)
            elif isinstance(obj, list):
                for item in obj:
                    extract_text_recursive(item, depth + 1)

        extract_text_recursive(asset_data)
        return " ".join(text_parts)

    def _evaluate_rule(
        self, rule: ClassificationRule, text_content: str, asset_data: Dict[str, Any], context: Dict[str, Any]
    ) -> Tuple[bool, float]:
        """
        Evaluate a classification rule against asset data.

        Returns:
            Tuple of (rule_matches, confidence_score)
        """
        matches = 0
        total_patterns = len(rule.patterns)

        if total_patterns == 0:
            return False, 0.0

        # Check pattern matches
        for pattern in rule.patterns:
            if re.search(pattern, text_content, re.IGNORECASE):
                matches += 1

        # Calculate base score
        pattern_score = matches / total_patterns

        # Apply rule conditions for score adjustment
        condition_bonus = self._evaluate_conditions(rule.conditions, asset_data, context)

        # Final score with priority weighting
        final_score = (pattern_score + condition_bonus) * (rule.priority / 100.0)

        # Rule matches if pattern score is above threshold
        rule_matches = pattern_score > 0.1  # At least 10% of patterns must match

        return rule_matches, min(final_score, 1.0)

    def _evaluate_conditions(
        self, conditions: Dict[str, Any], asset_data: Dict[str, Any], context: Dict[str, Any]
    ) -> float:
        """Evaluate rule conditions for scoring bonus."""
        if not conditions:
            return 0.0

        bonus = 0.0

        # Check for encryption requirements
        if conditions.get("requires_encryption") and self._has_encryption_indicators(asset_data):
            bonus += 0.2

        # Check for external access patterns
        if conditions.get("external_access") and self._has_external_access(asset_data):
            bonus += 0.15

        # Check for regulatory compliance indicators
        if conditions.get("regulatory_compliance") and self._has_compliance_indicators(asset_data):
            bonus += 0.1

        return min(bonus, 0.5)  # Cap bonus at 50%

    def _has_encryption_indicators(self, asset_data: Dict[str, Any]) -> bool:
        """Check if asset has encryption-related indicators."""
        text_content = self._extract_text_content(asset_data).lower()
        encryption_patterns = ["encrypt", "hash", "cipher", "secure", "protected"]
        return any(pattern in text_content for pattern in encryption_patterns)

    def _has_external_access(self, asset_data: Dict[str, Any]) -> bool:
        """Check if asset has external access indicators."""
        text_content = self._extract_text_content(asset_data).lower()
        access_patterns = ["api", "endpoint", "external", "public", "client", "web"]
        return any(pattern in text_content for pattern in access_patterns)

    def _has_compliance_indicators(self, asset_data: Dict[str, Any]) -> bool:
        """Check if asset has compliance-related indicators."""
        text_content = self._extract_text_content(asset_data).lower()
        compliance_patterns = ["audit", "compliance", "regulation", "policy", "gdpr", "hipaa"]
        return any(pattern in text_content for pattern in compliance_patterns)

    def _generate_recommendations(
        self, classification: SecurityClassification, matched_rules: List[str], risk_factors: List[str]
    ) -> List[str]:
        """Generate security recommendations based on classification."""
        recommendations = []

        if classification == SecurityClassification.CRITICAL:
            recommendations.extend(
                [
                    "Implement field-level encryption for sensitive data",
                    "Establish automatic rotation for credentials and keys",
                    "Deploy real-time monitoring and anomaly detection",
                    "Implement strict access controls with multi-factor authentication",
                    "Establish comprehensive audit logging for all access",
                ]
            )

        elif classification == SecurityClassification.IMPORTANT:
            recommendations.extend(
                [
                    "Implement role-based access controls",
                    "Establish regular access reviews and audits",
                    "Deploy monitoring for configuration changes",
                    "Implement data backup and recovery procedures",
                    "Establish change management processes",
                ]
            )

        elif classification == SecurityClassification.STANDARD:
            recommendations.extend(
                [
                    "Implement standard backup procedures",
                    "Deploy basic monitoring and alerting",
                    "Establish data retention policies",
                    "Implement basic access controls",
                    "Monitor for performance and availability",
                ]
            )

        else:  # DEVELOPMENT
            recommendations.extend(
                [
                    "Implement data anonymization for sensitive data",
                    "Establish environment isolation controls",
                    "Implement automatic cleanup procedures",
                    "Restrict access to development teams only",
                    "Ensure no production data in development environments",
                ]
            )

        # Add specific recommendations based on risk factors
        if "authentication_bypass" in risk_factors:
            recommendations.append("Implement multi-layered authentication controls")

        if "data_breach" in risk_factors:
            recommendations.append("Deploy data loss prevention (DLP) controls")

        if "privacy_violation" in risk_factors:
            recommendations.append("Implement privacy-by-design controls")

        if "regulatory_violation" in risk_factors:
            recommendations.append("Establish compliance monitoring and reporting")

        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)

        return unique_recommendations[:8]  # Limit to top 8 recommendations

    def _map_compliance_requirements(self, text_content: str, risk_factors: List[str]) -> List[str]:
        """Map asset to applicable compliance frameworks."""
        compliance_tags = []

        # Check GDPR applicability
        gdpr_indicators = ["personal", "email", "name", "user", "profile", "privacy"]
        if any(indicator in text_content for indicator in gdpr_indicators):
            compliance_tags.append("GDPR")

        # Check PCI DSS applicability
        pci_indicators = ["payment", "credit", "card", "financial", "billing"]
        if any(indicator in text_content for indicator in pci_indicators):
            compliance_tags.append("PCI_DSS")

        # Check HIPAA applicability
        hipaa_indicators = ["health", "medical", "patient", "clinical"]
        if any(indicator in text_content for indicator in hipaa_indicators):
            compliance_tags.append("HIPAA")

        # Check SOX applicability
        sox_indicators = ["financial", "audit", "accounting", "revenue"]
        if any(indicator in text_content for indicator in sox_indicators):
            compliance_tags.append("SOX")

        # Check ISO 27001 applicability
        iso_indicators = ["security", "risk", "control", "incident", "asset"]
        if any(indicator in text_content for indicator in iso_indicators):
            compliance_tags.append("ISO_27001")

        # Add compliance based on risk factors
        if "privacy_violation" in risk_factors or "gdpr_compliance" in risk_factors:
            compliance_tags.append("GDPR")

        if "financial_fraud" in risk_factors or "pci_compliance" in risk_factors:
            compliance_tags.append("PCI_DSS")

        return list(set(compliance_tags))  # Remove duplicates


def classify_data_assets(inventory_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience function to classify all data assets in an inventory.

    Args:
        inventory_data: Complete inventory data structure

    Returns:
        Enhanced inventory with security classifications
    """
    engine = SecurityClassificationEngine()
    return engine.classify_inventory(inventory_data)


# Example usage and testing
if __name__ == "__main__":
    # Example asset data for testing
    test_assets = [
        {
            "asset_id": "api_keys_table",
            "asset_type": "database_table",
            "asset_data": {
                "name": "api_key",
                "columns": [
                    {"name": "key_hash", "type": "VARCHAR"},
                    {"name": "api_key_value", "type": "VARCHAR"},
                    {"name": "user_id", "type": "INTEGER"},
                ],
            },
        },
        {
            "asset_id": "user_repository",
            "asset_type": "repository",
            "asset_data": {
                "repository_name": "UserRepository",
                "methods": ["get_user_by_email", "create_user", "update_password"],
                "crud_operations": {"read": True, "create": True, "update": True},
            },
        },
    ]

    engine = SecurityClassificationEngine()

    for asset in test_assets:
        result = engine.classify_asset(asset["asset_id"], asset["asset_type"], asset["asset_data"])

        print(f"\nAsset: {result.asset_id}")
        print(f"Classification: {result.classification.value}")
        print(f"Confidence: {result.confidence_score:.2f}")
        print(f"Risk Factors: {', '.join(result.risk_factors)}")
        print(f"Recommendations: {', '.join(result.recommendations[:3])}")
        print(f"Compliance: {', '.join(result.compliance_tags)}")
