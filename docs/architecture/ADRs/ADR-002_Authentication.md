Of course. Here is the next Architecture Decision Record for the standalone ViolentUTF API, focusing on the authentication strategy.

***

# ADR-002: Phased Authentication Strategy using JWT and API Keys

## Status
Accepted

## Authors
Tam Nguyen (Cybonto)

## Date
2025-07-27

## Stakeholders
* API Development Team
* Consumers of the API (Internal Teams, External Government Agencies, CI/CD Systems)
* GSA Compliance and Security Team
* Platform Operations Team

## Context
Following the decision to adopt a RESTful architecture (ADR-001), a robust and self-contained authentication strategy is required. The strategic spinoff of the ViolentUTF API mandates its complete independence from the mother repository's Keycloak identity provider. The new API must handle its own authentication to be fully functional.

The platform must securely identify two types of principals:
1.  **Human Users**: Interacting via scripts or future web interfaces.
2.  **Machine Clients**: Automated systems like CI/CD pipelines, scripts, and other government services that require non-interactive access.

A failure to implement a strong authentication mechanism would expose the platform to critical security risks, most notably `API2:2023 - Broken Authentication` as defined by OWASP. This decision is therefore foundational to the platform's security posture and its viability as a GSA-compliant service.

---
## Considered Options

### 1. Static API Keys (as the sole mechanism)
This approach involves providing clients with a single, long-lived secret token for all requests.

* **Pros**:
    * Simple for clients to use and for the server to implement initially.
* **Cons**:
    * **Poor Security**: Represents a significant liability. Keys are often hard-coded, shared, and rarely rotated, making them a prime target for leaks.
    * **No Standard for Permissions**: Lacks a standard way to embed or manage scopes and permissions.
    * **Difficult Revocation**: Revocation requires manual intervention and can be difficult to enforce across a distributed system.
    * **Verdict**: Unacceptable as the primary authentication method for a security-focused platform aiming for GSA compliance.

### 2. Standalone JWT (JSON Web Tokens) Implementation
This involves the API issuing its own short-lived, signed JWTs to clients after they provide credentials. The JWTs contain claims (e.g., user ID, roles) that can be verified without a database lookup.

* **Pros**:
    * **Stateless and Efficient**: Scales well and is highly performant, as the server does not need to query a database to validate a token on each request.
    * **Industry Standard**: Widely supported by libraries in all major languages.
    * **Self-Contained**: Allows the API to manage authentication independently, a core requirement of the spinoff.
* **Cons**:
    * **Revocation Complexity**: Being stateless, revoking a JWT before its expiration is non-trivial and typically requires a stateful blocklist, re-introducing a degree of state.
    * **Key Management is Critical**: The security of the entire system relies on the secure management of the token signing keys.

### 3. Full OAuth2 / OpenID Connect (OIDC) Integration
This approach involves integrating a formal identity provider and using the OAuth2 framework for delegated authorization and OIDC for identity.

* **Pros**:
    * **Gold Standard Security**: Represents the industry best practice for user authentication and authorization.
    * **Flexibility and Federation**: Easily supports Single Sign-On (SSO), third-party application integration, and federated identity from other providers.
* **Cons**:
    * **High Implementation Complexity**: Setting up a compliant OAuth2/OIDC provider and flow is significantly more complex and time-consuming than a direct JWT implementation.
    * **Delays Initial Launch**: The complexity would delay the delivery of a functional, standalone API, conflicting with the goal of a swift and effective extraction.

---
## Decision
The ViolentUTF API will implement a **phased, two-pronged initial authentication system** designed for immediate standalone functionality and future extensibility.

1.  **Initial Implementation (Phase 1):** The API will support two self-contained authentication mechanisms:
    * **Stateless JWT Bearer Tokens**: This will be the **primary mechanism** for authenticating sessions. Clients will exchange credentials for a short-lived access token and a long-lived refresh token.
    * **Managed API Keys**: This will be a **secondary mechanism** specifically for non-interactive machine-to-machine (M2M) clients. These keys will be long-lived but managed through dedicated API endpoints (create, list, revoke).

2.  **Future Evolution (Phase 2):** The architecture will be explicitly designed to incorporate a full **OAuth2/OIDC flow** in the future. The internal representation of users and principals will be decoupled from the authentication method, allowing OIDC to be added as another way to generate internal session tokens without requiring a rewrite of the core authorization logic.

---
## Rationale

This phased strategy was chosen because it provides the optimal balance of immediate functionality, robust security, and long-term strategic flexibility.

1.  **Enables Immediate Standalone Operation**: Implementing a self-contained JWT and API Key system allows the spun-off API to be functional and secure from day one, meeting the primary goal of the extraction without external dependencies. It avoids the significant delay that a full OIDC implementation would entail.

2.  **Addresses All Core Use Cases**: The dual mechanism of JWTs and API keys elegantly serves the two required principal types. JWTs are perfect for interactive sessions and temporary credentials, while API Keys provide a simple and secure method for headless, automated systems.

3.  **Future-Proofs the Architecture**: By explicitly planning for OIDC integration, we avoid architectural lock-in. This decision acknowledges that as the platform matures and acquires more complex user management needs (like SSO), a "gold standard" solution will be necessary. The initial design will pave the way for this evolution, making it an addition rather than a painful migration.

4.  **Adheres to the "Extract and Enhance" Philosophy**: Rather than just replicating a simple auth system, this approach mandates a secure-by-design implementation with best practices like short-lived tokens, refresh token rotation, and managed API keys, immediately elevating the security posture of the new service.

---
## Implementation Details

* **JWT Bearer Tokens**:
    * **Algorithm**: RS256 will be used, as asymmetric keys allow the signing key to be kept private while the public key for verification can be widely distributed.
    * **Claims**: Tokens will include standard claims (`sub`, `iat`, `exp`, `jti`) as well as custom claims for authorization (`roles`, `permissions`, `organization_id`).
    * **Lifespan**: Access tokens will be short-lived (e.g., 15-60 minutes). Refresh tokens will be long-lived (e.g., 7 days) and stored securely by the client.
    * **Revocation**: A token blocklist will be implemented using a distributed cache (e.g., Redis) to enable immediate revocation of specific tokens or all tokens for a user.

* **API Keys**:
    * **Format**: Keys will be generated with a prefix (e.g., `vutf-api_...`) for identifiability and high entropy. The full key will only be shown to the user once upon creation.
    * **Storage**: Keys will be stored in the database using a strong hashing algorithm (e.g., SHA-256). They will never be stored in plaintext.
    * **Management**: Dedicated, protected API endpoints will be created for users to create, list (metadata only), and revoke their own API keys.

---
## Consequences

* **Positive**:
    * The API is immediately self-sufficient, secure, and ready for deployment.
    * The authentication architecture is flexible and prepared for future requirements without needing a major redesign.
    * Clear separation of concerns between session-based authentication (JWT) and static credentials (API Keys).

* **Negative**:
    * The development team bears the full responsibility for correctly and securely implementing the token lifecycle management (issuance, validation, refresh, revocation), which is a non-trivial task.
    * The initial version will not support federated identity or SSO, which may be a requirement for some enterprise or government users in the long term.

* **Technical Impact**:
    * Requires the creation of several new core components: secure endpoints for token generation, a robust middleware for token validation, a system for managing API keys, and the infrastructure for a token blocklist.
    * This decision makes **ADR-003: Authorization and Access Control Model** the immediate next priority, as a clear strategy is needed to consume the `roles` and `permissions` claims established in this ADR.

---
## Related Artifacts/Decisions
* **ADR-001: Adopt REST for Standalone API Endpoints**: This decision is a direct follow-on, securing the endpoints established in ADR-001.
* **ADR-003: Authorization and Access Control Model**: The subsequent decision that will define how the identity established by this ADR is used to control access to resources.
* **ViolentUTF API Extraction & Spinoff Strategy**: The parent document driving the need for a self-contained authentication system.
