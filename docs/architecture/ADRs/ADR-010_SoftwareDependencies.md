# ADR-010: Automated Dependency Management and SCA Policy

## Status
Accepted

## Authors
Tam Nguyen (Cybonto)

## Date
2025-07-27

## Stakeholders
* API Development Team
* Platform Operations Team
* Security and Compliance Team
* Legal/Compliance Team

## Context
Modern applications are not built from scratch; they are assembled using a significant number of open-source and third-party libraries. Each of these dependencies represents a part of the application's "software supply chain" and a potential vector for attack. A single vulnerability in a dependency can lead to a full compromise of the platform.

As a standalone service aiming for GSA compliance, the ViolentUTF API must adopt a rigorous, proactive, and automated approach to managing its software supply chain. This policy is not optional; it is a fundamental security requirement to protect the platform and its users. The goal is to detect, assess, and remediate vulnerabilities and license compliance issues as early as possible in the development lifecycle.

---
## Considered Options

### 1. Manual/Ad-hoc Dependency Review
This approach relies on individual developers to manually check the libraries they add for known vulnerabilities or problematic licenses.

* **Pros**:
    * Requires no initial setup of tooling or process.
* **Cons**:
    * **Completely Unreliable**: It is not scalable, is highly error-prone, and is guaranteed to miss critical vulnerabilities.
    * **Not Auditable**: There is no way to prove that checks were performed or to enforce a consistent standard.
    * **Reactive, Not Proactive**: Issues are typically only found after an incident has occurred.
    * **Verdict**: Unacceptable and negligent for any serious production application, especially one handling sensitive security functions.

### 2. Automated SCA and Policy Enforcement
This approach involves integrating automated tools directly into the development lifecycle and CI/CD pipeline to continuously scan all dependencies. These scans check against comprehensive databases of known vulnerabilities and open-source license policies.

* **Pros**:
    * **Systematic and Reliable**: Automatically enforces security and compliance checks on every code change.
    * **Proactive Security**: Shifts security "left," finding and fixing issues before they reach production.
    * **Auditable and Enforceable**: Creates a clear, automated record of compliance and can be configured to block non-compliant code from being merged.
    * **Verdict**: The only viable and responsible approach for building and maintaining a secure application.

---
## Decision
The ViolentUTF API project will implement a formal, automated policy for Third-Party Dependency Management and Software Composition Analysis (SCA).

1.  **Tooling**: A **suite of automated SCA and static analysis tools** will be used for defense-in-depth.
2.  **CI/CD Integration**: These scans will be configured as a **mandatory, blocking quality gate** in the CI/CD pipeline. A pull request that fails a security or license scan cannot be merged.
3.  **Vulnerability Management**: A formal **Vulnerability Management Policy** with defined severity thresholds and remediation timelines will be established and enforced.
4.  **License Compliance**: A formal **License Compliance Policy** defining approved, restricted, and prohibited open-source licenses will be established and enforced.

---
## Rationale

This policy is foundational to the API's security posture and its goal of achieving GSA-level compliance.

1.  **Proactive Security posture**: This approach finds and fixes vulnerabilities early in the development process, which is significantly cheaper and more effective than reacting to incidents in production. It moves security from an afterthought to an integral part of the development workflow.

2.  **Automation Ensures Compliance**: Manual processes are destined to fail. By automating these checks and making them a blocking part of the CI/CD pipeline, we ensure that the defined security and legal policies are applied consistently and reliably to 100% of code changes.

3.  **Reduces Software Supply Chain Risk**: The use of open-source software is a massive productivity boost, but it comes with inherent risks. This policy directly mitigates the risk of a compromise via a known vulnerability in a dependency and reduces legal risks associated with open-source license misuse.

4.  **Fulfills Compliance Mandates**: A formal, automated SCA policy is a standard requirement for most security certifications and government compliance frameworks (e.g., FedRAMP). Adopting this policy from the start positions the API for successful future audits.

---
## Policy Details

### Tooling Suite
The project will use the following tools, integrated into the Git repository and CI/CD pipeline:
* **Dependabot**: For continuous, automated dependency monitoring on the main branch. It will automatically create pull requests to update packages when new, secure versions are available.
* **`pip-audit`**: To be run as a blocking step in the CI pipeline on every pull request. It will scan the exact set of installed packages against the Python Packaging Advisory Database for known vulnerabilities.
* **Static Code Security Analysis (SAST)**: Tools like **Bandit** (for common Python security issues) and **Semgrep** (for deeper, pattern-based analysis) will also be included as mandatory CI checks to secure our own code in addition to our dependencies.

### Vulnerability Management Policy
* **For New Code (Pull Requests)**: A pull request will be **blocked from merging** if the SCA scan detects any dependency with a **`CRITICAL`** or **`HIGH`** severity vulnerability. `MEDIUM` severity vulnerabilities will raise a warning and require acknowledgment or a remediation plan.
* **For Existing Code (Main Branch)**: Dependabot will continuously scan the main branch. The following Service Level Objectives (SLOs) for remediation will be enforced:
    * **`CRITICAL` Vulnerability**: Remediate within **7 days**.
    * **`HIGH` Vulnerability**: Remediate within **30 days**.
    * **`MEDIUM` Vulnerability**: Remediate within **90 days**.
    * **`LOW` Vulnerability**: Remediate on a best-effort basis.

### License Compliance Policy
* **Approved Licenses (Permissive)**: Dependencies using these licenses are automatically approved.
    * `MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`
* **Restricted Licenses (Weak Copyleft)**: These licenses require review and explicit approval from the legal/compliance team before being used.
    * `LGPL-2.1-only`, `LGPL-3.0-only`, `MPL-2.0`
* **Prohibited Licenses (Strong Copyleft / Other)**: These licenses are forbidden to avoid legal complications and the requirement to open-source our proprietary code.
    * `GPL-2.0`, `GPL-3.0`, `AGPL-3.0`, and other viral or ambiguous licenses.

---
## Consequences

* **Positive**:
    * The API's software supply chain is actively managed and significantly more secure.
    * The risk of compromise via a vulnerable third-party library is drastically reduced.
    * The project is protected from legal and compliance risks related to open-source licensing.
    * Provides a clear, auditable trail demonstrating security due diligence.

* **Negative**:
    * Can introduce friction and slow down development. Developers will be blocked by scans and may need to spend time upgrading dependencies or finding alternative libraries.
    * Scanners can produce false positives, which require time and effort to investigate and triage.

* **Technical Impact**:
    * The CI/CD pipeline must be configured with new, mandatory stages for security and license scanning.
    * The chosen tools (Dependabot, etc.) must be configured in the project's repository.
    * A formal process for handling exceptions (e.g., acknowledging a vulnerability with a compensating control) must be established.

---
## Related Artifacts/Decisions
* This policy is a cross-cutting concern that applies to the entire codebase and all preceding ADRs. It is fundamental to the security and integrity of the entire application.
