"""Enums for vulnerability management and security classification."""

from enum import Enum


class VulnerabilityCategory(str, Enum):
    """Categories of vulnerabilities based on attack vectors."""

    # Traditional Security Categories
    INJECTION = "injection"  # SQL, XSS, Command injection
    AUTHENTICATION = "authentication"  # Broken auth, weak credentials
    AUTHORIZATION = "authorization"  # Privilege escalation, access control
    DATA_EXPOSURE = "data_exposure"  # Sensitive data exposure
    CRYPTOGRAPHIC = "cryptographic"  # Weak crypto, cert issues
    CONFIGURATION = "configuration"  # Security misconfigurations

    # AI-Specific Categories (OWASP LLM Top 10)
    PROMPT_INJECTION = "prompt_injection"  # LLM01
    INSECURE_OUTPUT = "insecure_output"  # LLM02
    TRAINING_DATA_POISONING = "training_data_poisoning"  # LLM03
    MODEL_DOS = "model_dos"  # LLM04
    SUPPLY_CHAIN = "supply_chain"  # LLM05
    SENSITIVE_DISCLOSURE = "sensitive_disclosure"  # LLM06
    INSECURE_PLUGINS = "insecure_plugins"  # LLM07
    EXCESSIVE_AGENCY = "excessive_agency"  # LLM08
    OVERRELIANCE = "overreliance"  # LLM09
    MODEL_THEFT = "model_theft"  # LLM10

    # MITRE ATLAS Categories
    ADVERSARIAL_ML = "adversarial_ml"  # ML model attacks
    DATA_MANIPULATION = "data_manipulation"  # Training/inference data attacks
    MODEL_MANIPULATION = "model_manipulation"  # Model parameter attacks
    INFERENCE_ATTACKS = "inference_attacks"  # Model inversion, membership inference


class Severity(str, Enum):
    """Vulnerability severity levels based on CVSS and risk assessment."""

    CRITICAL = "critical"  # CVSS 9.0-10.0, immediate action required
    HIGH = "high"  # CVSS 7.0-8.9, action required soon
    MEDIUM = "medium"  # CVSS 4.0-6.9, action should be taken
    LOW = "low"  # CVSS 0.1-3.9, informational or minimal risk
    INFO = "info"  # CVSS 0.0, informational only


class VulnerabilityStatus(str, Enum):
    """Lifecycle status of vulnerability findings."""

    NEW = "new"  # Recently discovered, not yet triaged
    CONFIRMED = "confirmed"  # Verified as legitimate vulnerability
    IN_PROGRESS = "in_progress"  # Remediation in progress
    RESOLVED = "resolved"  # Fixed and verified
    FALSE_POSITIVE = "false_positive"  # Determined not to be a real vulnerability
    ACCEPTED_RISK = "accepted_risk"  # Risk accepted by business
    REOPEN = "reopen"  # Previously resolved but reoccurred


class RiskRating(str, Enum):
    """Business risk rating considering exploitability and impact."""

    CRITICAL_RISK = "critical_risk"  # Immediate business threat
    HIGH_RISK = "high_risk"  # Significant business threat
    MEDIUM_RISK = "medium_risk"  # Moderate business threat
    LOW_RISK = "low_risk"  # Minor business threat
    MINIMAL_RISK = "minimal_risk"  # Negligible business threat


class ScanStatus(str, Enum):
    """Status of security scans."""

    PENDING = "pending"  # Scan scheduled but not started
    RUNNING = "running"  # Scan in progress
    COMPLETED = "completed"  # Scan finished successfully
    FAILED = "failed"  # Scan encountered errors
    CANCELLED = "cancelled"  # Scan was stopped by user
    TIMEOUT = "timeout"  # Scan exceeded time limit


class ScanType(str, Enum):
    """Types of security scans supported."""

    # Automated Tool Scans
    PYRIT = "pyrit"  # PyRIT AI red-teaming scan
    GARAK = "garak"  # Garak LLM vulnerability scanner
    STATIC_ANALYSIS = "static_analysis"  # Static code analysis
    DYNAMIC_ANALYSIS = "dynamic_analysis"  # Dynamic application testing

    # Manual Assessment Types
    PENETRATION_TEST = "penetration_test"  # Manual pentesting
    CODE_REVIEW = "code_review"  # Manual code review
    ARCHITECTURE_REVIEW = "architecture_review"  # Design review

    # Compliance Scans
    OWASP_LLM = "owasp_llm"  # OWASP LLM Top 10 assessment
    MITRE_ATLAS = "mitre_atlas"  # MITRE ATLAS technique mapping
    NIST_AI_RMF = "nist_ai_rmf"  # NIST AI Risk Management Framework


class AttackVector(str, Enum):
    """Attack vectors for vulnerability classification."""

    # Network vectors
    NETWORK = "network"  # Remote network exploitation
    ADJACENT = "adjacent"  # Adjacent network access required
    LOCAL = "local"  # Local access required
    PHYSICAL = "physical"  # Physical access required

    # AI-specific vectors
    PROMPT = "prompt"  # Malicious prompts/input
    MODEL = "model"  # Direct model manipulation
    TRAINING_DATA = "training_data"  # Training data manipulation
    INFERENCE = "inference"  # Inference-time attacks
    API = "api"  # API-level attacks

    # Traditional vectors
    WEB_APPLICATION = "web_application"  # Web app vulnerabilities
    SOCIAL_ENGINEERING = "social_engineering"  # Human factor attacks
    SUPPLY_CHAIN = "supply_chain"  # Third-party dependencies


class OWASPLLMCategory(str, Enum):
    """OWASP LLM Top 10 categories."""

    LLM01_PROMPT_INJECTION = "LLM01"  # Prompt Injection
    LLM02_INSECURE_OUTPUT = "LLM02"  # Insecure Output Handling
    LLM03_TRAINING_POISONING = "LLM03"  # Training Data Poisoning
    LLM04_MODEL_DOS = "LLM04"  # Model Denial of Service
    LLM05_SUPPLY_CHAIN = "LLM05"  # Supply Chain Vulnerabilities
    LLM06_SENSITIVE_DISCLOSURE = "LLM06"  # Sensitive Information Disclosure
    LLM07_INSECURE_PLUGINS = "LLM07"  # Insecure Plugin Design
    LLM08_EXCESSIVE_AGENCY = "LLM08"  # Excessive Agency
    LLM09_OVERRELIANCE = "LLM09"  # Overreliance
    LLM10_MODEL_THEFT = "LLM10"  # Model Theft


class MITREATLASTactic(str, Enum):
    """MITRE ATLAS tactics for AI/ML security."""

    RECONNAISSANCE = "reconnaissance"  # Information gathering
    RESOURCE_DEVELOPMENT = "resource_development"  # Develop resources for attacks
    INITIAL_ACCESS = "initial_access"  # Get initial foothold
    MODEL_ACCESS = "model_access"  # Access to ML model
    EXECUTION = "execution"  # Execute malicious code/inputs
    PERSISTENCE = "persistence"  # Maintain access
    DEFENSE_EVASION = "defense_evasion"  # Avoid detection
    DISCOVERY = "discovery"  # Learn about environment
    COLLECTION = "collection"  # Gather data
    ML_ATTACK_STAGING = "ml_attack_staging"  # Prepare ML-specific attacks
    EXFILTRATION = "exfiltration"  # Data theft
    IMPACT = "impact"  # Disrupt, degrade, or destroy
