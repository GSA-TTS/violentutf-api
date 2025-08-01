# Architectural Violation Hotspots Analysis Report

**Generated:** 2025-07-31 18:30:46 UTC
**Repository:** `.`
**Analysis Period:** 30 days (since 2025-07-01)

## Executive Summary

This report analyzes Git commit history to identify architectural violation hotspots - code areas with frequent architectural violations that require focused audit attention.

### Key Findings

- **Total Commits Analyzed:** 54
- **Violation Commits Found:** 11 (20.4% of all commits)
- **Files with Violations:** 100
- **Unique ADRs Violated:** 6

## Top 10 High-Risk Files

The following files represent the highest architectural risk based on a multi-factor risk score combining violation frequency, recency, severity, and code complexity:

| Rank | File Path | Risk Score | Violations | Complexity | Primary ADRs Violated |
|------|-----------|------------|------------|------------|----------------------|
| 1 | `app/api/endpoints/auth.py` | 37.74 | 4 | 8.0 | ADR-002 (2), MIDDLEWARE-VIOLATIONS (1), ADR-005 (1) |
| 2 | `app/core/input_validation.py` | 17.69 | 2 | 6.91 | ADR-005 (1), ADR-002 (1) |
| 3 | `app/middleware/metrics.py` | 15.92 | 2 | 7.0 | MIDDLEWARE-VIOLATIONS (1), ADR-002 (1) |
| 4 | `app/models/user.py` | 14.68 | 4 | 3.15 | ADR-002 (2), GENERAL-SECURITY (1), ADR-008 (1) |
| 5 | `app/repositories/base.py` | 14.68 | 2 | 6.35 | ADR-008 (1), ADR-002 (1) |
| 6 | `app/main.py` | 14.15 | 4 | 3.0 | ADR-002 (2), MIDDLEWARE-VIOLATIONS (1), ADR-005 (1) |
| 7 | `app/models/mixins.py` | 12.12 | 3 | 3.58 | GENERAL-SECURITY (1), ADR-008 (1), ADR-002 (1) |
| 8 | `app/core/field_sanitization.py` | 10.67 | 1 | 9.17 | ADR-005 (1) |
| 9 | `app/middleware/csrf.py` | 9.17 | 2 | 3.43 | ADR-002 (2) |
| 10 | `app/api/endpoints/auth_validated.py` | 8.92 | 1 | 7.67 | ADR-005 (1) |

## Detailed File Analysis

### High-Risk Files (Risk Score > 5.0)

#### `app/api/endpoints/auth.py`

- **Risk Score:** 37.74 (HIGH)
- **Total Violations:** 4
- **Complexity Score:** 8.0
- **Violation Period:** 2025-07-24 to 2025-07-31

**ADR Violations:**
- **ADR-002** (Authentication Strategy): 2 violations (severity: 1.4)
- **MIDDLEWARE-VIOLATIONS** (Middleware Architecture Violations): 1 violations (severity: 1.1)
- **ADR-005** (Rate Limiting): 1 violations (severity: 1.2)

#### `app/core/input_validation.py`

- **Risk Score:** 17.69 (HIGH)
- **Total Violations:** 2
- **Complexity Score:** 6.91
- **Violation Period:** 2025-07-29 to 2025-07-31

**ADR Violations:**
- **ADR-005** (Rate Limiting): 1 violations (severity: 1.2)
- **ADR-002** (Authentication Strategy): 1 violations (severity: 1.4)

#### `app/middleware/metrics.py`

- **Risk Score:** 15.92 (HIGH)
- **Total Violations:** 2
- **Complexity Score:** 7.0
- **Violation Period:** 2025-07-24 to 2025-07-31

**ADR Violations:**
- **MIDDLEWARE-VIOLATIONS** (Middleware Architecture Violations): 1 violations (severity: 1.1)
- **ADR-002** (Authentication Strategy): 1 violations (severity: 1.4)

#### `app/models/user.py`

- **Risk Score:** 14.68 (HIGH)
- **Total Violations:** 4
- **Complexity Score:** 3.15
- **Violation Period:** 2025-07-25 to 2025-07-31

**ADR Violations:**
- **ADR-002** (Authentication Strategy): 2 violations (severity: 1.4)
- **GENERAL-SECURITY** (General Security Violations): 1 violations (severity: 1.3)
- **ADR-008** (Logging and Auditing): 1 violations (severity: 1.1)

#### `app/repositories/base.py`

- **Risk Score:** 14.68 (HIGH)
- **Total Violations:** 2
- **Complexity Score:** 6.35
- **Violation Period:** 2025-07-25 to 2025-07-31

**ADR Violations:**
- **ADR-008** (Logging and Auditing): 1 violations (severity: 1.1)
- **ADR-002** (Authentication Strategy): 1 violations (severity: 1.4)

#### `app/main.py`

- **Risk Score:** 14.15 (HIGH)
- **Total Violations:** 4
- **Complexity Score:** 3.0
- **Violation Period:** 2025-07-24 to 2025-07-31

**ADR Violations:**
- **ADR-002** (Authentication Strategy): 2 violations (severity: 1.4)
- **MIDDLEWARE-VIOLATIONS** (Middleware Architecture Violations): 1 violations (severity: 1.1)
- **ADR-005** (Rate Limiting): 1 violations (severity: 1.2)

#### `app/models/mixins.py`

- **Risk Score:** 12.12 (HIGH)
- **Total Violations:** 3
- **Complexity Score:** 3.58
- **Violation Period:** 2025-07-25 to 2025-07-31

**ADR Violations:**
- **GENERAL-SECURITY** (General Security Violations): 1 violations (severity: 1.3)
- **ADR-008** (Logging and Auditing): 1 violations (severity: 1.1)
- **ADR-002** (Authentication Strategy): 1 violations (severity: 1.4)

#### `app/core/field_sanitization.py`

- **Risk Score:** 10.67 (HIGH)
- **Total Violations:** 1
- **Complexity Score:** 9.17
- **Violation Period:** 2025-07-29 to 2025-07-29

**ADR Violations:**
- **ADR-005** (Rate Limiting): 1 violations (severity: 1.2)

#### `app/middleware/csrf.py`

- **Risk Score:** 9.17 (HIGH)
- **Total Violations:** 2
- **Complexity Score:** 3.43
- **Violation Period:** 2025-07-28 to 2025-07-31

**ADR Violations:**
- **ADR-002** (Authentication Strategy): 2 violations (severity: 1.4)

#### `app/api/endpoints/auth_validated.py`

- **Risk Score:** 8.92 (HIGH)
- **Total Violations:** 1
- **Complexity Score:** 7.67
- **Violation Period:** 2025-07-29 to 2025-07-29

**ADR Violations:**
- **ADR-005** (Rate Limiting): 1 violations (severity: 1.2)

#### `app/services/mfa_policy_service.py`

- **Risk Score:** 8.87 (HIGH)
- **Total Violations:** 1
- **Complexity Score:** 6.33
- **Violation Period:** 2025-07-31 to 2025-07-31

**ADR Violations:**
- **ADR-002** (Authentication Strategy): 1 violations (severity: 1.4)

#### `app/core/decorators/sql_injection.py`

- **Risk Score:** 8.83 (HIGH)
- **Total Violations:** 1
- **Complexity Score:** 7.58
- **Violation Period:** 2025-07-29 to 2025-07-29

**ADR Violations:**
- **ADR-005** (Rate Limiting): 1 violations (severity: 1.2)

#### `app/core/config.py`

- **Risk Score:** 8.7 (HIGH)
- **Total Violations:** 2
- **Complexity Score:** 4.23
- **Violation Period:** 2025-07-24 to 2025-07-29

**ADR Violations:**
- **MIDDLEWARE-VIOLATIONS** (Middleware Architecture Violations): 1 violations (severity: 1.1)
- **ADR-005** (Rate Limiting): 1 violations (severity: 1.2)

#### `app/middleware/authentication.py`

- **Risk Score:** 8.62 (HIGH)
- **Total Violations:** 2
- **Complexity Score:** 3.22
- **Violation Period:** 2025-07-28 to 2025-07-31

**ADR Violations:**
- **ADR-002** (Authentication Strategy): 2 violations (severity: 1.4)

#### `app/repositories/user.py`

- **Risk Score:** 8.48 (HIGH)
- **Total Violations:** 2
- **Complexity Score:** 3.67
- **Violation Period:** 2025-07-25 to 2025-07-31

**ADR Violations:**
- **ADR-008** (Logging and Auditing): 1 violations (severity: 1.1)
- **ADR-002** (Authentication Strategy): 1 violations (severity: 1.4)

#### `app/api/endpoints/mfa_policies.py`

- **Risk Score:** 8.4 (HIGH)
- **Total Violations:** 1
- **Complexity Score:** 6.0
- **Violation Period:** 2025-07-31 to 2025-07-31

**ADR Violations:**
- **ADR-002** (Authentication Strategy): 1 violations (severity: 1.4)

#### `app/api/endpoints/oauth.py`

- **Risk Score:** 8.4 (HIGH)
- **Total Violations:** 1
- **Complexity Score:** 6.0
- **Violation Period:** 2025-07-31 to 2025-07-31

**ADR Violations:**
- **ADR-002** (Authentication Strategy): 1 violations (severity: 1.4)

#### `app/core/cache.py`

- **Risk Score:** 8.4 (HIGH)
- **Total Violations:** 1
- **Complexity Score:** 6.0
- **Violation Period:** 2025-07-31 to 2025-07-31

**ADR Violations:**
- **ADR-002** (Authentication Strategy): 1 violations (severity: 1.4)

#### `app/middleware/audit.py`

- **Risk Score:** 8.24 (HIGH)
- **Total Violations:** 1
- **Complexity Score:** 5.89
- **Violation Period:** 2025-07-31 to 2025-07-31

**ADR Violations:**
- **ADR-002** (Authentication Strategy): 1 violations (severity: 1.4)

#### `tools/pre_audit/historical_analyzer.py`

- **Risk Score:** 7.8 (HIGH)
- **Total Violations:** 1
- **Complexity Score:** 5.57
- **Violation Period:** 2025-07-31 to 2025-07-31

**ADR Violations:**
- **ADR-002** (Authentication Strategy): 1 violations (severity: 1.4)

## ADR Violation Summary

The following table shows which architectural decisions are being violated most frequently:

| ADR ID | ADR Name | Violation Count | Severity Weight | Description |
|--------|----------|----------------|----------------|-------------|
| ADR-002 | Authentication Strategy | 2 | 1.4 | Violations related to JWT authentication implementation |
| MIDDLEWARE-VIOLATIONS | Middleware Architecture Violations | 1 | 1.1 | Violations related to middleware ordering or implementation |
| GENERAL-SECURITY | General Security Violations | 1 | 1.3 | General security-related architectural violations |
| ADR-008 | Logging and Auditing | 1 | 1.1 | Violations related to structured logging and audit requirements |
| ADR-005 | Rate Limiting | 1 | 1.2 | Violations related to rate limiting implementation |
| ADR-SEC-001 | Input Validation Violations | 1 | 1.3 | Violations related to input validation and sanitization |

## Recommendations

### Immediate Actions (High Priority)

1. **Focus Audit Efforts:** Prioritize manual review of the top 5 high-risk files listed above
2. **Refactoring Targets:** Consider breaking down complex files (complexity > 10) with high violation counts
3. **Pattern Analysis:** Investigate why ADR-002 are being violated most frequently

### Medium-Term Improvements

1. **Developer Training:** Focus on ADRs with highest violation counts
2. **Tooling Integration:** Implement pre-commit hooks to catch violations early
3. **Documentation Review:** Update ADR documentation for frequently violated principles

### Tracking Effectiveness

- **Baseline Established:** This report serves as the baseline for measuring improvement
- **Re-run Frequency:** Recommended monthly analysis to track trends
- **Success Metrics:** Target 20% reduction in high-risk files within 3 months

## Methodology

This analysis uses a multi-factor risk scoring model:

```
Risk Score = (Frequency × Recency Weight) × Severity Weight × Complexity Score
```

- **Frequency:** Total violation count in the analysis period
- **Recency Weight:** Decay factor giving more weight to recent violations (1.0 = today, 0.1 = 30 days ago)
- **Severity Weight:** ADR-specific impact multiplier (configured in violation_patterns.yml)
- **Complexity Score:** Average cyclomatic complexity from static analysis

Files are considered "hotspots" when they have both high violation frequency AND high complexity, indicating they are both unstable and difficult to maintain.

---

*This report was generated by the ViolentUTF API Historical Analyzer*
*For questions or issues, please refer to the ADR Compliance Audit documentation*
