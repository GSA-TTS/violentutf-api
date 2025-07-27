# ADR-006: JSON as the Exclusive Data Serialization Format

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
A decision on a single, standardized data serialization format is a fundamental requirement for building a predictable, reliable, and usable API. This format defines the "language" used to structure data in all API request and response bodies. The choice directly impacts developer experience, performance, security, and compatibility with tooling.

This decision is a direct consequence of adopting a RESTful architecture (ADR-001). While REST is technically format-agnostic, modern best practices have converged on a clear industry standard. For the standalone ViolentUTF API, which must prioritize ease of integration and developer experience, selecting a single, well-supported format is essential.

---
## Considered Options

### 1. JSON (JavaScript Object Notation)
A lightweight, text-based, human-readable data interchange format. It has become the de facto standard for modern web APIs.

* **Pros**:
    * **Universal Support**: Natively supported by virtually every modern programming language and platform.
    * **Human-Readable**: Easy for developers to read and debug during development and troubleshooting.
    * **Excellent Tooling**: Seamlessly integrated with the entire API ecosystem, including OpenAPI/Swagger, Postman, and browser developer tools.
    * **Lightweight**: Less verbose than alternatives like XML.
* **Cons**:
    * **Performance**: As a text-based format, it is inherently less performant (larger payload size, slower parsing) than binary formats.

### 2. XML (eXtensible Markup Language)
A markup language that defines a set of rules for encoding documents in a format that is both human-readable and machine-readable. It was a common choice for older enterprise and SOAP-based web services.

* **Pros**:
    * Mature and well-established in certain enterprise environments.
    * Supports schemas (XSD) and transformations (XSLT).
* **Cons**:
    * **Verbose**: Significantly more verbose and heavyweight than JSON, leading to larger network payloads.
    * **Complex Parsing**: More complex to parse, which can impact performance.
    * **Increased Security Risk**: Presents a more complex parsing attack surface, including vulnerabilities like XML External Entity (XXE) injection, which requires careful mitigation.

### 3. Protocol Buffers (Protobuf)
A binary serialization format developed by Google, designed for high performance.

* **Pros**:
    * **High Performance**: Extremely efficient, producing very small payloads that can be parsed very quickly.
    * **Strongly Typed**: Requires a formal schema definition (`.proto` file) that enforces a strict contract.
* **Cons**:
    * **Not Human-Readable**: The binary format makes it impossible for developers to inspect or debug payloads without specialized tooling.
    * **High Friction for Public APIs**: Requires clients to have access to the `.proto` schema files and use a Protobuf compiler to generate client-side code, creating a significant barrier to entry.
    * **Poor Fit for REST/OpenAPI**: While not impossible, integration with standard REST tooling is not a natural fit.

---
## Decision
The ViolentUTF API will exclusively use **JSON (JavaScript Object Notation)** as the data serialization format for all API request and response bodies.

All endpoints will produce and consume the `application/json` media type. Other formats such as XML or Protobuf will not be supported for the public-facing API.

---
## Rationale
JSON is the unambiguous and optimal choice for this API, aligning perfectly with its strategic goals of developer-friendliness, broad compatibility, and security.

1.  **Industry Standard and Developer Experience**: JSON is the lingua franca of modern web APIs. Its universal support means that developers consuming our API can use their preferred language and tools with minimal friction. This ease of use is paramount for driving adoption within government and external teams.

2.  **Seamless OpenAPI and Tooling Integration**: The decision to adhere to OpenAPI standards (ADR-004) makes JSON the only logical choice. JSON is the native format for OpenAPI specifications and is what tools like Swagger UI are built to render and interact with. This synergy creates a superior, interactive documentation experience out-of-the-box.

3.  **Human Readability for Debugging**: The ability for a developer to easily read and understand an API payload in logs, browser tools, or a cURL output is an invaluable feature for development and troubleshooting. This transparency simplifies the integration process significantly compared to an opaque binary format.

4.  **Optimal Balance of Performance and Usability**: While Protobuf offers higher raw performance, this comes at a steep cost to usability and developer experience. For a public-facing REST API, where network latency is often a greater factor than parsing speed, the immense benefits of JSON's simplicity and tooling support far outweigh the marginal performance gains of a binary format.

5.  **Simplified Security Model**: JSON has a simpler and more well-understood security model than XML. Its straightforward key-value structure presents a smaller attack surface for parsing-related vulnerabilities.

---
## Consequences

* **Positive**:
    * The API will be extremely easy for new developers and client systems to adopt and integrate.
    * The development lifecycle for both the API and its clients will be accelerated due to the rich ecosystem of supporting tools and libraries.
    * Debugging and observability are greatly simplified because request and response payloads are human-readable.

* **Negative**:
    * The API will not be suitable for extreme low-latency or low-bandwidth environments where every byte and microsecond counts. This is an accepted trade-off, as it is not the target use case.
    * Payloads will be larger than they would be with a binary format, leading to slightly increased network bandwidth usage.

* **Technical Impact**:
    * All Pydantic models and data transfer objects within the FastAPI application must be designed for clean JSON serialization.
    * The OpenAPI specification generated by the application will exclusively define `application/json` as the media type for all operations.
    * No additional libraries or dependencies for other serialization formats will be needed, keeping the application's dependency tree lean.

---
## Related Artifacts/Decisions
* **ADR-001: Adopt REST for Standalone API Endpoints**: The choice of JSON is the standard and expected convention for modern REST APIs.
* **ADR-004: URI Path Versioning Strategy**: The choice of JSON aligns with providing a clear, well-documented API via OpenAPI, which was a factor in the versioning strategy.
