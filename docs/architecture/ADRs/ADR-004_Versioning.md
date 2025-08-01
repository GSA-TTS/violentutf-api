Of course. Here is the next Architecture Decision Record for the standalone ViolentUTF API, focusing on the versioning strategy.

***

# ADR-004: URI Path Versioning Strategy

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
* Documentation Team

## Context
As a long-lived service, the ViolentUTF API will evolve. New features will be added, data models will change, and existing functionality may be improved or replaced. A deliberate versioning strategy is essential to manage this evolution gracefully, allowing existing clients to continue functioning without interruption while enabling the adoption of new capabilities. This stability is critical for maintaining user trust, especially in a government context.

This decision directly follows the adoption of a RESTful architecture (ADR-001). The chosen versioning strategy must be clear, pragmatic, and easily expressible within the OpenAPI 3.x specification, which ViolentUTF follows for its API documentation.

---
## Considered Options

### 1. URI Path Versioning
The API version is included directly in the URL path.
* **Example**: `GET /api/v1/scans`
* **Pros**:
    * **Explicit and Discoverable**: The version is immediately obvious to developers, making it easy to browse, debug, and use.
    * **Excellent Tooling Support**: Natively supported by the entire ecosystem of API tools, including OpenAPI/Swagger, Postman, and API gateways. This simplifies documentation and interactive testing.
    * **Simple Caching**: Caching is straightforward as different API versions have unique, unambiguous URLs.
* **Cons**:
    * **URI "Purity"**: Some architectural purists argue that a URI should represent a resource, not a specific version of its contract.
    * **Potential Code Duplication**: Can lead to duplicated routing or controller logic if the backend is not structured carefully to handle multiple versions.

### 2. Custom Request Header Versioning
The client specifies the desired version in a custom HTTP header.
* **Example**: `GET /api/scans` with header `Api-Version: 1`
* **Pros**:
    * Keeps URIs "clean" and version-agnostic.
* **Cons**:
    * **Less Discoverable**: The version is "hidden" in a header, making it less obvious to developers Browse the API documentation.
    * **Complex Caching**: Requires cache keys to `Vary` based on the custom header, which is not universally supported by all caching proxies.
    * **Friction for Clients**: Requires custom client configuration, which can be an extra point of failure or confusion.

### 3. Accept Header Versioning (Content Negotiation)
The client requests a specific version of a resource using a custom media type in the standard `Accept` header.
* **Example**: `GET /api/scans` with header `Accept: application/vnd.violentutf.v1+json`
* **Pros**:
    * **Theoretically "Correct"**: Uses the standard HTTP mechanism for content negotiation as intended by the protocol's authors.
* **Cons**:
    * **Impractical and Obscure**: This is the least common and most poorly understood method. Many standard HTTP clients and libraries do not make it easy to manipulate the `Accept` header in this way, leading to high friction for developers.
    * **Poor Tooling Support**: Generally not well-supported by common API tools.

---
## Decision
The ViolentUTF API will adopt **URI Path Versioning** for all releases containing breaking changes.

The version will be mandatory and will be the first element in the API path after the `/api` prefix. The format will be `v[major_version]`, where the version is an integer.

* **Example**: `https://api.violentutf.gsa.gov/api/v1/scans`

Non-breaking, backward-compatible changes (e.g., adding a new optional field to a response or adding a completely new endpoint) will **not** require a new version. The current major version will simply be updated.

---
## Rationale

This decision was made based on pragmatism, developer experience, and industry-standard practices.

1.  **Explicitness and Clarity**: URI path versioning is the most transparent method. It makes the version of the API being used unambiguous to everyone involved, from the client developer to the operations engineer debugging logs. There is no "magic" hidden in headers.

2.  **Superior Tooling and OpenAPI Compatibility**: This is the primary driver. URI path versioning is natively and seamlessly supported by OpenAPI and its ecosystem of tools like Swagger UI. This makes it trivial to generate clear, interactive documentation and ensures that consumers of our GSA-compliant API have the best possible developer experience.

3.  **Simplicity of Implementation**: Routing requests based on a path prefix is a standard, well-supported feature in web frameworks like FastAPI. It also simplifies the implementation of backend services and caching infrastructure, as the unique URL provides a clear identifier for each versioned resource.

4.  **Industry Standard**: While other methods exist, URI path versioning is overwhelmingly the most common approach for public-facing APIs. Adopting this convention reduces friction and surprises for new developers and integrating systems. The "URI purity" argument against this method is considered an academic concern that is far outweighed by the practical benefits of clarity and usability.

---
## Implementation Details

* **Definition of a Breaking Change**: A new major version (e.g., v1 -> v2) will be introduced ONLY when a backward-incompatible change is made. Examples include:
    * Removing an endpoint.
    * Renaming an endpoint.
    * Changing the data type of a field in a response (e.g., `string` to `integer`).
    * Removing a field from a response.
    * Adding a new required field to a request body.
    * Changing authentication or authorization rules for an existing endpoint.

* **Definition of a Non-Breaking Change**: These changes can be added to the existing major version. Examples include:
    * Adding a new endpoint.
    * Adding a new, optional field to a request body.
    * Adding a new field to a JSON response object.
    * Changing the content of error messages.

* **Deprecation Policy**: To ensure a smooth transition for clients, a clear deprecation policy will be enforced.
    * When a new major version (e.g., `v2`) is released, the previous version (`v1`) will be considered **deprecated**.
    * The deprecated version will be supported for a minimum of **6 months**.
    * All responses from a deprecated version will include a `Deprecation` header (e.g., `Deprecation: true`) and a `Warning` header indicating its planned sunset date.

---
## Consequences

* **Positive**:
    * The API's version is always explicit and self-documenting in the request.
    * Client integrations are more stable, as they are protected from unannounced breaking changes.
    * OpenAPI documentation will be clear, accurate, and easy to generate for each version.

* **Negative**:
    * Can lead to some code duplication in the backend if not managed with a clean architecture (e.g., using shared business logic services called by version-specific controllers).
    * The number of active endpoints that must be maintained and secured grows with each new version that is still within its support window.

* **Technical Impact**:
    * The FastAPI application's routing layer must be structured to handle versioned prefixes (e.g., using `APIRouter` for each version).
    * The CI/CD pipeline must be capable of deploying and managing multiple API versions concurrently.
    * A process must be established for generating and publishing version-specific OpenAPI documentation.

---
## Related Artifacts/Decisions
* **ADR-001: Adopt REST for Standalone API Endpoints**: This versioning strategy is a core tenet of managing the lifecycle of the REST API established in ADR-001.
