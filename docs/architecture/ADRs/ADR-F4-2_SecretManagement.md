# ADR-F4.2: Centralized Secrets Management for Target System Credentials

## Status

Proposed

## Authors

ViolentUTF API Team

## Date

2025-07-27

## Stakeholders

  * API Development Team
  * Platform Operations Team
  * Security and Compliance Team
  * GSA Compliance and Security Team

## Context

To perform its core function, the ViolentUTF platform must handle and use highly sensitive customer credentials, such as API keys and authentication tokens for third-party AI providers (e.g., OpenAI, Anthropic). The storage, handling, and lifecycle of these secrets are of paramount importance.

A breach that exposes these customer credentials would be a catastrophic security failure, resulting in a complete loss of customer trust and severe reputational and legal consequences. Therefore, the architecture for managing these secrets must be designed with the highest level of security, adhering to industry best practices for "zero trust" and least privilege.

-----

## Considered Options

### 1\. Encrypted in Application Database

This common approach involves storing secrets in a column in the main application database, encrypted with an application-level key. The decryption key is typically stored in a configuration file or environment variable on the application server.

  * **Pros**:
      * Appears simple to implement and keeps all data in one place.
  * **Cons**:
      * **Creates a Single Point of Compromise**: This is a critical flaw. An attacker who gains control of the application server (via a code vulnerability or other means) can access the decryption key and then decrypt **all customer secrets** stored in the database.
      * **Poor Auditing and Access Control**: Lacks the fine-grained access control and detailed audit trails that are standard in dedicated secrets management systems.
      * **Verdict**: While better than storing secrets in plaintext, this approach is a well-known anti-pattern and is not sufficiently secure for the level of risk involved.

### 2\. Dedicated Secrets Manager

This approach involves using a separate, hardened, dedicated service built specifically for storing and managing secrets. Examples include HashiCorp Vault, AWS Secrets Manager, or Google Cloud Secret Manager. The application authenticates to this external service to retrieve secrets on a just-in-time basis.

  * **Pros**:

      * **Drastically Reduced Attack Surface**: Secrets are not stored in the same place as application data. An application server compromise does not automatically lead to a full secrets compromise.
      * **Centralized, Fine-Grained Access Control**: Allows for creating strict policies (e.g., "this specific service is only allowed to read this specific secret").
      * **Comprehensive Auditing**: Provides a detailed, immutable audit log of every single secret access, which is critical for security investigations and compliance.
      * **Industry Best Practice**: This is the undisputed standard for professional secrets management.

  * **Cons**:

      * **Increased Operational Complexity**: Introduces a new, critical piece of infrastructure that must be deployed, maintained, and monitored.

-----

## Decision

The ViolentUTF platform will use a **Dedicated Secrets Management Service** as the central, secure vault for all user-provided credentials for target systems.

1.  **Externalized Storage**: All sensitive customer credentials will be stored exclusively within a dedicated secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager). Secrets will **never** be stored in the main application database, not even in an encrypted form.
2.  **Storage by Reference**: The main application database will only store a **non-sensitive pointer** (a reference or path) to the secret's location in the external secrets manager.
3.  **Just-in-Time (JIT) Retrieval**: Application services (e.g., background workers) will retrieve secrets from the manager on a just-in-time basis immediately before they are needed. Secrets will only be held in memory for the minimal time required and will never be written to disk.
4.  **Abstraction Layer**: The application will implement a **secrets management abstraction layer**, allowing the specific secrets manager backend to be configurable based on the deployment environment (e.g., a local Vault for development, AWS Secrets Manager for production on AWS).

-----

## Rationale

This decision is non-negotiable for building a trustworthy, enterprise-grade security platform.

1.  **Adherence to the Principle of Least Privilege**: A dedicated secrets manager allows us to enforce strict, fine-grained access policies. An application service can be granted a machine identity (e.g., an IAM Role) that gives it permission to read *only the specific secrets it needs for a given job*, and nothing more. This dramatically limits the "blast radius" of a potential compromise.

2.  **Provides Critical Auditability**: For a security and compliance-focused platform, a detailed, immutable audit trail of every secret access is essential. Dedicated secrets managers provide this capability out-of-the-box, allowing us to answer exactly who or what accessed a specific secret and when. This is a core requirement for GSA compliance and incident response.

3.  **Breaks the Chain of Compromise**: By externalizing secrets, we break the attack chain. An attacker who compromises the main application database will only find useless pointers, not the encrypted secrets and the key to unlock them. They would need to mount a separate, much more difficult attack against the hardened secrets manager itself.

4.  **Enables Secure and Scalable Automation**: The JIT retrieval pattern is a secure and scalable way to provide credentials to ephemeral services like our background workers and sandboxed containers. It avoids insecure practices like passing secrets in environment variables or hard-coding them in configurations.

-----

## Implementation Details

### High-Level Workflow

1.  **Storage**: When a user submits a new credential via the API, the application server authenticates to the secrets manager, writes the secret to a secure path (e.g., `/vutf/org/{organization_id}/targets/{target_id}`), and receives back a pointer. The application server then saves this non-sensitive pointer in the main relational database.
2.  **Retrieval**: When a background worker needs to run a test:
    a. It retrieves the test configuration from the relational database, which includes the secret pointer.
    b. The worker authenticates itself to the secrets manager using its own secure machine identity (e.g., a Kubernetes Service Account identity or an AWS IAM Role).
    c. It uses the pointer to request the specific secret from the manager.
    d. It uses the secret in memory to instantiate the required Provider Plugin (from ADR-F1.3).
    e. The secret is purged from memory as soon as the API call to the target model is complete.

### Abstraction Layer

A simple interface will be created to decouple the application from a specific secrets manager implementation.

```python
from abc import ABC, abstractmethod

class SecretsManagerClient(ABC):
    """Abstract interface for storing and retrieving secrets."""

    @abstractmethod
    def store_secret(self, path: str, secret_data: dict) -> None:
        """Stores a secret at the given path."""
        pass

    @abstractmethod
    def retrieve_secret(self, path: str) -> dict:
        """Retrieves a secret from the given path."""
        pass
```

-----

## Consequences

  * **Positive**:

      * The security posture of the platform regarding customer credentials is elevated to the industry best-practice standard.
      * The system becomes highly auditable and more easily compliant with stringent security frameworks.
      * The risk of a catastrophic, all-encompassing credential breach is drastically reduced.

  * **Negative**:

      * **Introduces a Critical Infrastructure Dependency**: The secrets manager becomes a Tier 0 service. If it is unavailable, the platform cannot execute any tests that require credentials. It must be deployed in a highly available configuration.
      * Increases operational complexity and cost.

  * **Technical Impact**:

      * A secrets management abstraction layer and concrete implementations for different backends must be developed.
      * All application services that handle credentials must be refactored to use this new service.
      * The platform's CI/CD and deployment automation must be configured with a secure way to bootstrap the initial identities needed for the application to authenticate to the secrets manager.

-----

## Related Artifacts/Decisions

  * This ADR provides the secure mechanism to supply credentials to the plugins defined in **ADR-F1.3 (Integration Architecture)**.
  * It is a critical component for securely passing secrets to the isolated environments defined in **ADR-F4.1 (Sandboxing Architecture)**.
  * This decision underpins the entire security model of the platform.
