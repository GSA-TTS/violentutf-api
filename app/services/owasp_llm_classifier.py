"""OWASP LLM Top 10 vulnerability classification service."""

import re
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from structlog.stdlib import get_logger

from app.core.enums import (
    AttackVector,
    OWASPLLMCategory,
    Severity,
    VulnerabilityCategory,
)

logger = get_logger(__name__)


class ClassificationConfidence(Enum):
    """Classification confidence levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class OWASPLLMClassifier:
    """Service for classifying vulnerabilities according to OWASP LLM Top 10."""

    def __init__(self) -> None:
        """Initialize the OWASP LLM classifier with pattern matching rules."""
        self.classification_patterns = self._initialize_patterns()
        self.severity_mappings = self._initialize_severity_mappings()

    def _initialize_patterns(self) -> Dict[OWASPLLMCategory, Dict[str, Any]]:
        """Initialize pattern matching rules for OWASP LLM categories."""
        return {
            OWASPLLMCategory.LLM01_PROMPT_INJECTION: {
                "keywords": [
                    "prompt injection",
                    "jailbreak",
                    "system prompt",
                    "ignore previous",
                    "disregard instructions",
                    "malicious prompt",
                    "prompt manipulation",
                    "role playing",
                    "developer mode",
                    "act as",
                    "pretend to be",
                    "bypass filter",
                    "escape sequence",
                    "prompt attack",
                ],
                "patterns": [
                    r"ignore\s+(previous|all|above)\s+instructions?",
                    r"system\s*:\s*[^\.]*\bact\s+as\b",
                    r"developer\s+mode|admin\s+mode|god\s+mode",
                    r"\bdisregard\s+(rules|safety|guidelines)",
                    r"jailbreak|jail\s*break",
                    r"prompt\s+injection",
                ],
                "severity": Severity.CRITICAL,
                "attack_vector": AttackVector.PROMPT,
                "description": "Manipulating AI model via crafted inputs to bypass safety filters",
            },
            OWASPLLMCategory.LLM02_INSECURE_OUTPUT: {
                "keywords": [
                    "output validation",
                    "xss",
                    "cross-site scripting",
                    "html injection",
                    "script tag",
                    "javascript injection",
                    "output encoding",
                    "response injection",
                    "insecure output",
                    "untrusted output",
                    "output sanitization",
                ],
                "patterns": [
                    r"<script[^>]*>.*?</script>",
                    r"javascript\s*:\s*[^;]*",
                    r"on\w+\s*=\s*[\"'][^\"']*[\"']",
                    r"output.*validation",
                    r"response.*injection",
                ],
                "severity": Severity.HIGH,
                "attack_vector": AttackVector.WEB_APPLICATION,
                "description": "Insufficient validation of model outputs leading to injection attacks",
            },
            OWASPLLMCategory.LLM03_TRAINING_POISONING: {
                "keywords": [
                    "training data",
                    "data poisoning",
                    "training poisoning",
                    "backdoor",
                    "model poisoning",
                    "dataset manipulation",
                    "training corruption",
                    "malicious training",
                    "data integrity",
                    "training bias",
                ],
                "patterns": [
                    r"training\s+(data|set|corpus).*poison",
                    r"backdoor.*model",
                    r"data\s+poison.*training",
                    r"corrupt.*training.*data",
                    r"malicious.*dataset",
                ],
                "severity": Severity.HIGH,
                "attack_vector": AttackVector.TRAINING_DATA,
                "description": "Malicious data injection during model training to influence behavior",
            },
            OWASPLLMCategory.LLM04_MODEL_DOS: {
                "keywords": [
                    "denial of service",
                    "dos",
                    "resource exhaustion",
                    "model overload",
                    "computational attack",
                    "resource consumption",
                    "availability attack",
                    "service disruption",
                    "model flooding",
                    "rate limiting",
                ],
                "patterns": [
                    r"denial\s+of\s+service|dos\s+attack",
                    r"resource\s+exhaustion",
                    r"model\s+(overload|flooding)",
                    r"computational\s+attack",
                    r"availability\s+attack",
                ],
                "severity": Severity.MEDIUM,
                "attack_vector": AttackVector.API,
                "description": "Resource exhaustion attacks targeting AI model availability",
            },
            OWASPLLMCategory.LLM05_SUPPLY_CHAIN: {
                "keywords": [
                    "supply chain",
                    "third party",
                    "dependency",
                    "model provider",
                    "external service",
                    "vendor risk",
                    "third-party component",
                    "upstream dependency",
                    "model marketplace",
                    "untrusted source",
                ],
                "patterns": [
                    r"supply\s+chain.*vulnerabilit",
                    r"third\s*party.*model",
                    r"external\s+(service|provider).*risk",
                    r"dependency.*vulnerabilit",
                    r"untrusted.*source",
                ],
                "severity": Severity.MEDIUM,
                "attack_vector": AttackVector.SUPPLY_CHAIN,
                "description": "Vulnerabilities in AI model supply chain and dependencies",
            },
            OWASPLLMCategory.LLM06_SENSITIVE_DISCLOSURE: {
                "keywords": [
                    "sensitive information",
                    "data leakage",
                    "information disclosure",
                    "privacy violation",
                    "personal data",
                    "confidential information",
                    "data exposure",
                    "information leakage",
                    "sensitive data",
                ],
                "patterns": [
                    r"sensitive\s+(information|data).*disclos",
                    r"data\s+(leakage|exposure)",
                    r"information\s+(disclosure|leakage)",
                    r"privacy\s+violation",
                    r"personal\s+data.*expos",
                ],
                "severity": Severity.HIGH,
                "attack_vector": AttackVector.API,
                "description": "Unauthorized disclosure of sensitive information through model outputs",
            },
            OWASPLLMCategory.LLM07_INSECURE_PLUGINS: {
                "keywords": [
                    "plugin",
                    "extension",
                    "add-on",
                    "third-party integration",
                    "plugin security",
                    "insecure plugin",
                    "plugin vulnerability",
                    "extension vulnerability",
                    "unsafe plugin",
                ],
                "patterns": [
                    r"plugin.*vulnerabilit",
                    r"insecure\s+plugin",
                    r"extension.*security",
                    r"unsafe\s+plugin",
                    r"plugin.*exploit",
                ],
                "severity": Severity.MEDIUM,
                "attack_vector": AttackVector.API,
                "description": "Security vulnerabilities in AI model plugins and extensions",
            },
            OWASPLLMCategory.LLM08_EXCESSIVE_AGENCY: {
                "keywords": [
                    "excessive agency",
                    "over-privileged",
                    "unauthorized action",
                    "autonomous behavior",
                    "permission escalation",
                    "privilege abuse",
                    "excessive permissions",
                    "unintended action",
                    "agency control",
                ],
                "patterns": [
                    r"excessive\s+(agency|permission)",
                    r"over.privileg",
                    r"unauthorized\s+action",
                    r"permission\s+escalation",
                    r"unintended\s+action",
                ],
                "severity": Severity.HIGH,
                "attack_vector": AttackVector.MODEL,
                "description": "AI model performing actions beyond intended scope or permissions",
            },
            OWASPLLMCategory.LLM09_OVERRELIANCE: {
                "keywords": [
                    "overreliance",
                    "over-reliance",
                    "blind trust",
                    "lack of oversight",
                    "insufficient validation",
                    "unchecked output",
                    "automated decision",
                    "human oversight",
                    "validation failure",
                ],
                "patterns": [
                    r"over.relian",
                    r"blind\s+trust",
                    r"lack.*oversight",
                    r"insufficient\s+validation",
                    r"unchecked\s+output",
                ],
                "severity": Severity.MEDIUM,
                "attack_vector": AttackVector.MODEL,
                "description": "Excessive reliance on AI model outputs without proper validation",
            },
            OWASPLLMCategory.LLM10_MODEL_THEFT: {
                "keywords": [
                    "model theft",
                    "model extraction",
                    "intellectual property",
                    "model stealing",
                    "unauthorized access",
                    "model reverse engineering",
                    "proprietary model",
                    "model piracy",
                    "model copying",
                ],
                "patterns": [
                    r"model\s+(theft|stealing|extraction)",
                    r"intellectual\s+property.*theft",
                    r"unauthorized\s+access.*model",
                    r"model\s+(reverse\s+engineering|piracy)",
                    r"proprietary\s+model.*theft",
                ],
                "severity": Severity.MEDIUM,
                "attack_vector": AttackVector.MODEL,
                "description": "Unauthorized extraction or theft of AI model intellectual property",
            },
        }

    def _initialize_severity_mappings(self) -> Dict[OWASPLLMCategory, Severity]:
        """Initialize default severity mappings for OWASP LLM categories."""
        return {
            OWASPLLMCategory.LLM01_PROMPT_INJECTION: Severity.CRITICAL,
            OWASPLLMCategory.LLM02_INSECURE_OUTPUT: Severity.HIGH,
            OWASPLLMCategory.LLM03_TRAINING_POISONING: Severity.HIGH,
            OWASPLLMCategory.LLM04_MODEL_DOS: Severity.MEDIUM,
            OWASPLLMCategory.LLM05_SUPPLY_CHAIN: Severity.MEDIUM,
            OWASPLLMCategory.LLM06_SENSITIVE_DISCLOSURE: Severity.HIGH,
            OWASPLLMCategory.LLM07_INSECURE_PLUGINS: Severity.MEDIUM,
            OWASPLLMCategory.LLM08_EXCESSIVE_AGENCY: Severity.HIGH,
            OWASPLLMCategory.LLM09_OVERRELIANCE: Severity.MEDIUM,
            OWASPLLMCategory.LLM10_MODEL_THEFT: Severity.MEDIUM,
        }

    def classify_vulnerability(
        self,
        title: str,
        description: Optional[str] = None,
        proof_of_concept: Optional[str] = None,
        attack_scenario: Optional[str] = None,
        ai_model_affected: Optional[str] = None,
        prompt_pattern: Optional[str] = None,
    ) -> Tuple[Optional[OWASPLLMCategory], ClassificationConfidence, float]:
        """
        Classify a vulnerability according to OWASP LLM Top 10.

        Args:
            title: Vulnerability title
            description: Vulnerability description
            proof_of_concept: Proof of concept details
            attack_scenario: Attack scenario description
            ai_model_affected: Affected AI model information
            prompt_pattern: Malicious prompt pattern

        Returns:
            Tuple of (OWASP category, confidence level, confidence score)
        """
        try:
            # Combine all text for analysis
            text_fields = [
                title or "",
                description or "",
                proof_of_concept or "",
                attack_scenario or "",
                ai_model_affected or "",
                prompt_pattern or "",
            ]
            combined_text = " ".join(text_fields).lower()

            if not combined_text.strip():
                return None, ClassificationConfidence.LOW, 0.0

            # Calculate scores for each OWASP LLM category
            category_scores = {}

            for category, patterns in self.classification_patterns.items():
                score = self._calculate_category_score(combined_text, patterns)
                if score > 0:
                    category_scores[category] = score

            if not category_scores:
                return None, ClassificationConfidence.LOW, 0.0

            # Get the highest scoring category
            best_category = max(category_scores.keys(), key=lambda k: category_scores[k])
            best_score = category_scores[best_category]

            # Determine confidence level based on score
            confidence_level = self._determine_confidence_level(best_score)

            logger.info(
                "OWASP LLM classification completed",
                category=best_category.value,
                score=best_score,
                confidence=confidence_level.value,
            )

            return best_category, confidence_level, best_score

        except Exception as e:
            logger.error("Error in OWASP LLM classification", error=str(e))
            return None, ClassificationConfidence.LOW, 0.0

    def _calculate_category_score(self, text: str, patterns: Dict[str, Any]) -> float:
        """Calculate match score for a specific OWASP LLM category."""
        score = 0.0

        # Keyword matching (base score)
        keyword_matches = 0
        for keyword in patterns.get("keywords", []):
            if keyword.lower() in text:
                keyword_matches += 1

        # Scale keyword score
        if keyword_matches > 0:
            score += min(keyword_matches * 0.2, 1.0)

        # Pattern matching (higher weight)
        pattern_matches = 0
        for pattern in patterns.get("patterns", []):
            try:
                if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                    pattern_matches += 1
            except re.error:
                # Skip invalid regex patterns
                continue

        # Scale pattern score (higher weight than keywords)
        if pattern_matches > 0:
            score += min(pattern_matches * 0.4, 2.0)

        return min(score, 5.0)  # Cap at 5.0

    def _determine_confidence_level(self, score: float) -> ClassificationConfidence:
        """Determine confidence level based on classification score."""
        if score >= 3.0:
            return ClassificationConfidence.VERY_HIGH
        elif score >= 2.0:
            return ClassificationConfidence.HIGH
        elif score >= 1.0:
            return ClassificationConfidence.MEDIUM
        else:
            return ClassificationConfidence.LOW

    def get_category_details(self, category: OWASPLLMCategory) -> Dict[str, Any]:
        """Get detailed information about an OWASP LLM category."""
        if category not in self.classification_patterns:
            return {}

        pattern_info = self.classification_patterns[category]

        return {
            "category": category.value,
            "name": self._get_category_name(category),
            "severity": pattern_info.get("severity", Severity.MEDIUM).value,
            "attack_vector": pattern_info.get("attack_vector", AttackVector.NETWORK).value,
            "description": pattern_info.get("description", ""),
            "keywords": pattern_info.get("keywords", []),
            "detection_methods": self._get_detection_methods(category),
            "remediation_guidance": self._get_remediation_guidance(category),
            "prevention_measures": self._get_prevention_measures(category),
        }

    def _get_category_name(self, category: OWASPLLMCategory) -> str:
        """Get human-readable name for OWASP LLM category."""
        name_mapping = {
            OWASPLLMCategory.LLM01_PROMPT_INJECTION: "Prompt Injection",
            OWASPLLMCategory.LLM02_INSECURE_OUTPUT: "Insecure Output Handling",
            OWASPLLMCategory.LLM03_TRAINING_POISONING: "Training Data Poisoning",
            OWASPLLMCategory.LLM04_MODEL_DOS: "Model Denial of Service",
            OWASPLLMCategory.LLM05_SUPPLY_CHAIN: "Supply Chain Vulnerabilities",
            OWASPLLMCategory.LLM06_SENSITIVE_DISCLOSURE: "Sensitive Information Disclosure",
            OWASPLLMCategory.LLM07_INSECURE_PLUGINS: "Insecure Plugin Design",
            OWASPLLMCategory.LLM08_EXCESSIVE_AGENCY: "Excessive Agency",
            OWASPLLMCategory.LLM09_OVERRELIANCE: "Overreliance",
            OWASPLLMCategory.LLM10_MODEL_THEFT: "Model Theft",
        }
        return name_mapping.get(category, category.value)

    def _get_detection_methods(self, category: OWASPLLMCategory) -> List[str]:
        """Get detection methods for specific OWASP LLM category."""
        detection_mapping = {
            OWASPLLMCategory.LLM01_PROMPT_INJECTION: [
                "Pattern matching for injection keywords",
                "Semantic analysis of input prompts",
                "Response monitoring for bypassed filters",
                "Behavior analysis for unexpected responses",
            ],
            OWASPLLMCategory.LLM02_INSECURE_OUTPUT: [
                "Output validation and sanitization",
                "Content analysis for malicious patterns",
                "XSS and injection scanning",
                "Response filtering mechanisms",
            ],
            OWASPLLMCategory.LLM03_TRAINING_POISONING: [
                "Data validation and provenance tracking",
                "Anomaly detection in training data",
                "Model behavior monitoring",
                "Training data integrity checks",
            ],
            OWASPLLMCategory.LLM04_MODEL_DOS: [
                "Resource consumption monitoring",
                "Rate limiting enforcement",
                "Request pattern analysis",
                "Performance degradation detection",
            ],
            OWASPLLMCategory.LLM05_SUPPLY_CHAIN: [
                "Dependency vulnerability scanning",
                "Third-party component auditing",
                "Supply chain integrity verification",
                "Vendor security assessments",
            ],
            OWASPLLMCategory.LLM06_SENSITIVE_DISCLOSURE: [
                "Data classification and tagging",
                "Output content filtering",
                "Privacy impact assessments",
                "Sensitive data detection algorithms",
            ],
            OWASPLLMCategory.LLM07_INSECURE_PLUGINS: [
                "Plugin security scanning",
                "Permission and capability auditing",
                "Third-party extension reviews",
                "Runtime behavior monitoring",
            ],
            OWASPLLMCategory.LLM08_EXCESSIVE_AGENCY: [
                "Permission boundary enforcement",
                "Action authorization checks",
                "Automated decision auditing",
                "Privilege escalation detection",
            ],
            OWASPLLMCategory.LLM09_OVERRELIANCE: [
                "Human-in-the-loop validation",
                "Confidence scoring mechanisms",
                "Output verification processes",
                "Decision audit trails",
            ],
            OWASPLLMCategory.LLM10_MODEL_THEFT: [
                "API access monitoring",
                "Unusual query pattern detection",
                "Model fingerprinting protection",
                "Intellectual property safeguards",
            ],
        }
        return detection_mapping.get(category, ["Generic vulnerability scanning"])

    def _get_remediation_guidance(self, category: OWASPLLMCategory) -> str:
        """Get remediation guidance for specific OWASP LLM category."""
        remediation_mapping = {
            OWASPLLMCategory.LLM01_PROMPT_INJECTION: "Implement input validation, output filtering, and prompt sanitization. Use system-level prompts that cannot be overridden by user input.",
            OWASPLLMCategory.LLM02_INSECURE_OUTPUT: "Sanitize and validate all model outputs before use. Implement proper encoding and filtering for different output contexts.",
            OWASPLLMCategory.LLM03_TRAINING_POISONING: "Implement data validation, source verification, and training monitoring. Use trusted data sources and validate data integrity.",
            OWASPLLMCategory.LLM04_MODEL_DOS: "Implement rate limiting, resource quotas, and monitoring. Use caching and load balancing to prevent resource exhaustion.",
            OWASPLLMCategory.LLM05_SUPPLY_CHAIN: "Regularly audit dependencies, use trusted sources, and implement supply chain security controls. Monitor for known vulnerabilities.",
            OWASPLLMCategory.LLM06_SENSITIVE_DISCLOSURE: "Implement data classification, output filtering, and privacy controls. Review and sanitize training data for sensitive information.",
            OWASPLLMCategory.LLM07_INSECURE_PLUGINS: "Conduct security reviews of plugins, implement proper authorization, and monitor plugin behavior. Use sandboxing for third-party extensions.",
            OWASPLLMCategory.LLM08_EXCESSIVE_AGENCY: "Implement least privilege principles, proper authorization checks, and human oversight for critical actions. Define clear boundaries for automated behavior.",
            OWASPLLMCategory.LLM09_OVERRELIANCE: "Implement human validation processes, confidence scoring, and verification mechanisms. Provide appropriate uncertainty indicators.",
            OWASPLLMCategory.LLM10_MODEL_THEFT: "Implement access controls, query monitoring, and intellectual property protection. Use rate limiting and anomaly detection.",
        }
        return remediation_mapping.get(
            category,
            "Follow general security best practices and vendor recommendations.",
        )

    def _get_prevention_measures(self, category: OWASPLLMCategory) -> str:
        """Get prevention measures for specific OWASP LLM category."""
        prevention_mapping = {
            OWASPLLMCategory.LLM01_PROMPT_INJECTION: "Design robust system prompts, implement input validation, and use defensive prompt engineering techniques.",
            OWASPLLMCategory.LLM02_INSECURE_OUTPUT: "Implement output encoding, validation, and sanitization by default. Use context-aware filtering mechanisms.",
            OWASPLLMCategory.LLM03_TRAINING_POISONING: "Use trusted data sources, implement data validation pipelines, and maintain data provenance records.",
            OWASPLLMCategory.LLM04_MODEL_DOS: "Design with resource constraints in mind, implement proper rate limiting, and use monitoring and alerting.",
            OWASPLLMCategory.LLM05_SUPPLY_CHAIN: "Establish vendor security requirements, conduct regular security assessments, and maintain an inventory of dependencies.",
            OWASPLLMCategory.LLM06_SENSITIVE_DISCLOSURE: "Implement privacy by design, data minimization principles, and comprehensive data governance.",
            OWASPLLMCategory.LLM07_INSECURE_PLUGINS: "Establish secure development standards for plugins, implement security reviews, and use secure plugin architectures.",
            OWASPLLMCategory.LLM08_EXCESSIVE_AGENCY: "Design with appropriate constraints, implement authorization frameworks, and maintain human oversight controls.",
            OWASPLLMCategory.LLM09_OVERRELIANCE: "Establish validation processes, provide uncertainty indicators, and maintain human decision authority for critical processes.",
            OWASPLLMCategory.LLM10_MODEL_THEFT: "Implement access controls from design phase, use monitoring and detection systems, and establish legal protections.",
        }
        return prevention_mapping.get(
            category,
            "Apply security-by-design principles and follow industry best practices.",
        )

    def get_all_categories_info(self) -> List[Dict[str, Any]]:
        """Get detailed information for all OWASP LLM categories."""
        return [self.get_category_details(category) for category in OWASPLLMCategory]

    def suggest_taxonomy_mapping(
        self, vulnerability_title: str, vulnerability_description: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Suggest a vulnerability taxonomy mapping based on OWASP LLM classification.

        Returns a suggested taxonomy structure that can be used to create
        a VulnerabilityTaxonomy record.
        """
        classification_result = self.classify_vulnerability(vulnerability_title, vulnerability_description)

        owasp_category, confidence, score = classification_result

        if not owasp_category or confidence == ClassificationConfidence.LOW:
            return None

        category_details = self.get_category_details(owasp_category)

        return {
            "name": category_details.get("name", vulnerability_title),
            "category": self._map_owasp_to_category(owasp_category),
            "description": category_details.get("description", vulnerability_description),
            "owasp_id": owasp_category,
            "is_ai_specific": True,
            "attack_vector": category_details.get("attack_vector", "network"),
            "base_severity": category_details.get("severity", "medium"),
            "classification_confidence": score,
            "detection_methods": str(category_details.get("detection_methods", [])),
            "remediation_guidance": category_details.get("remediation_guidance", ""),
            "prevention_measures": category_details.get("prevention_measures", ""),
        }

    def _map_owasp_to_category(self, owasp_category: OWASPLLMCategory) -> VulnerabilityCategory:
        """Map OWASP LLM category to internal vulnerability category."""
        mapping = {
            OWASPLLMCategory.LLM01_PROMPT_INJECTION: VulnerabilityCategory.PROMPT_INJECTION,
            OWASPLLMCategory.LLM02_INSECURE_OUTPUT: VulnerabilityCategory.INSECURE_OUTPUT,
            OWASPLLMCategory.LLM03_TRAINING_POISONING: VulnerabilityCategory.TRAINING_DATA_POISONING,
            OWASPLLMCategory.LLM04_MODEL_DOS: VulnerabilityCategory.MODEL_DOS,
            OWASPLLMCategory.LLM05_SUPPLY_CHAIN: VulnerabilityCategory.SUPPLY_CHAIN,
            OWASPLLMCategory.LLM06_SENSITIVE_DISCLOSURE: VulnerabilityCategory.SENSITIVE_DISCLOSURE,
            OWASPLLMCategory.LLM07_INSECURE_PLUGINS: VulnerabilityCategory.INSECURE_PLUGINS,
            OWASPLLMCategory.LLM08_EXCESSIVE_AGENCY: VulnerabilityCategory.EXCESSIVE_AGENCY,
            OWASPLLMCategory.LLM09_OVERRELIANCE: VulnerabilityCategory.OVERRELIANCE,
            OWASPLLMCategory.LLM10_MODEL_THEFT: VulnerabilityCategory.MODEL_THEFT,
        }
        return mapping.get(owasp_category, VulnerabilityCategory.ADVERSARIAL_ML)
