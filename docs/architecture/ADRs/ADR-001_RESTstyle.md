Of course. Here is the ADR without citations.

***

# ADR-001: Adopt REST for Standalone API Endpoints

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

## Context
This decision is being made in the context of a strategic spinoff, where the ViolentUTF API is being extracted from its original monolithic repository (`violentutf`) into a new, standalone service (`violentutf-api`). The new API must operate independently without its previous dependencies on an APISIX gateway or a Keycloak identity provider.

The choice of an API architectural style is a foundational decision that dictates interaction patterns, performance, and the overall developer experience for a new service. For an AI red teaming API, the architecture must support complex, structured operations (e.g., defining multi-stage attacks) while offering the simplicity required for easy integration into automated scripts and CI/CD pipelines. The existing API within the mother repository is already built on FastAPI, which naturally favors a RESTful approach. Therefore, this ADR addresses whether to reaffirm and enhance this RESTful style for the new standalone context or to adopt a different one.

---
## Considered Options

### 1. Representational State Transfer (REST)
A mature, resource-oriented architectural style that uses standard HTTP methods (GET, POST, PUT, DELETE). It is the de facto standard for web APIs.

* **Pros**:
    * **Unparalleled Ecosystem**: Massive support from tools like Postman and Swagger/OpenAPI, and compatibility with virtually all HTTP clients.
    * **Simplicity and Predictability**: The resource-oriented structure is widely understood by developers, reducing the learning curve.
    * **Statelessness**: Promotes scalability, as the server does not need to maintain client session state between requests.
    * **Standalone Feasibility**: Security (auth tokens, API keys) and policies (rate limiting) can be implemented effectively in application middleware, which is a requirement for the new API that will not have a gateway.
* **Cons**:
    * **Over/Under-fetching**: Can lead to "chatty" interactions where a client either receives more data than needed or must make multiple requests to get all required data.
    * **Verbose Payloads**: Relies on text-based formats like JSON, which can be less efficient than binary formats.

### 2. GraphQL
A query language for APIs that allows clients to request exactly the data they need in a single round trip.

* **Pros**:
    * **Efficient Data Fetching**: Solves the over/under-fetching problem by design, which is highly advantageous for complex red teaming scenarios.
    * **Strongly Typed Schema**: The schema provides a single source of truth, enhances security through server-side validation, and enables excellent developer tooling like GraphiQL.
* **Cons**:
    * **Server-Side Complexity**: Implementation of caching, security, and query resolution is significantly more complex than in REST.
    * **New Security Vectors**: Introduces risks like complex query Denial-of-Service attacks that require specialized mitigation. This poses a risk for a security-focused GSA repository.

### 3. gRPC (gRPC Remote Procedure Calls)
A high-performance RPC framework using Protocol Buffers for binary serialization over HTTP/2.

* **Pros**:
    * **Highest Performance**: Excels in low-latency, high-throughput scenarios due to its efficient binary format.
    * **Strongly Typed Contracts**: Uses `.proto` files to define strict service contracts.
* **Cons**:
    * **Poor Developer Experience for Public APIs**: The binary format is not human-readable, making it difficult to debug for external users.
    * **Limited Ecosystem**: Lacks the broad, tool-agnostic support of REST, especially for browser-based clients and simple scripting.

---
## Decision
The ViolentUTF API will adopt and enhance a **RESTful architectural style** for all public-facing endpoints. This decision reaffirms the existing approach but adapts it to meet the new requirements of a standalone, GSA-compliant service.

The API will standardize on JSON for all data serialization and will implement a clear URI path versioning strategy (e.g., `/api/v1/...`) to manage future changes gracefully.

---
## Rationale
This decision is based on a combination of technical merit, risk mitigation, and strategic alignment with the extraction goals.

1.  **Continuity and Reduced Risk**: The existing API is already built on FastAPI, a framework optimized for creating RESTful services. Continuing with REST minimizes the risk and effort of the spinoff by building on a known foundation rather than re-architecting from scratch.

2.  **Alignment with Standalone Operation**: REST is exceptionally well-suited for the new standalone architecture. Key functions previously handled by the APISIX gateway, such as authentication, authorization, and rate limiting, have well-established patterns for implementation directly within a RESTful application's middleware. This aligns with the "Extract and Enhance" philosophy of the spinoff strategy.

3.  **Broadest Compatibility and Ease of Adoption**: As a future GSA-compliant repository, the API must be easily consumable by a wide range of government and external systems. REST's massive ecosystem and reliance on standard HTTP ensure maximum compatibility and a minimal learning curve for new adopters.

4.  **Mitigation of Weaknesses**: The primary drawbacks of REST (over-fetching and chattiness) will be actively mitigated through established design patterns, as outlined in the extraction strategy. This includes implementing comprehensive **pagination, filtering, and field selection** capabilities in our endpoints.

5.  **Security Maturity**: The security landscape for REST APIs is extremely well-understood, with established best practices like the OWASP API Security Top 10 serving as a clear guide. This provides a mature and defensible foundation for building a secure service, which is paramount for an AI red teaming platform. In contrast, GraphQL presents newer and less-understood security challenges.

---
## Consequences

* **Positive**:
    * Development velocity will be high due to familiarity with the paradigm.
    * A vast pool of existing documentation, tools, and developer talent can be leveraged.
    * The path to achieving GSA compliance is clearer due to REST's well-defined security best practices.
    * The API will be immediately usable with standard tools (cURL, Postman) without requiring special client libraries.

* **Negative**:
    * The API may be less efficient for clients with highly complex data-retrieval needs compared to GraphQL.
    * Disciplined design will be required to prevent "endpoint sprawl" and to ensure consistency across the API surface.
    * The responsibility for implementing security, rate limiting, and other policies now falls entirely on the application code, increasing its complexity compared to relying on a gateway.

* **Technical Impact**:
    * Middleware for authentication (JWT/API Keys), authorization (RBAC/ABAC), rate limiting, and security headers must be implemented as part of the core application.
    * Future foundational ADRs will be required for API Versioning (`ADR-004`), Authentication (`ADR-002`), and Authorization (`ADR-003`) to build upon this REST foundation.

---
## Related Artifacts/Decisions
* **ViolentUTF API Extraction & Spinoff Strategy**: This ADR is a direct consequence of the goals and architectural changes outlined in this strategy document.
* **ADR-004: API Versioning Strategy**: The decision to use REST necessitates a formal versioning strategy.
* **ADR-002: Phased Authentication Strategy**: The choice of REST influences the implementation of authentication mechanisms (e.g., using HTTP `Authorization` headers).
