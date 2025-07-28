# ADR-009: Standardized Error Handling with RFC 7807

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

A predictable, consistent, and secure error handling strategy is a cornerstone of a high-quality API. Inconsistent error responses make client-side development brittle and frustrating, as consumers are forced to write custom parsing logic for every potential failure mode.

Furthermore, poorly designed error messages can create significant security vulnerabilities by leaking sensitive internal information, such as stack traces, database query errors, or internal file paths. This information can provide attackers with valuable reconnaissance for further exploits.

This ADR defines a single, standardized format for all client-facing error responses across the API, ensuring a robust and secure developer experience.

-----

## Considered Options

### 1\. Ad-hoc / Custom Error Objects

This approach involves using a custom, non-standard JSON structure for error responses. This is the pattern currently used in the mother repository.

  * **Example**: `{ "error": true, "message": "...", "error_code": "...", ... }`
  * **Pros**:
      * Familiar to the existing development team.
  * **Cons**:
      * **Non-Standard**: Reinvents the wheel and forces every client to learn and implement logic for a proprietary format.
      * **Brittle**: Without a formal standard, the format can diverge over time across different endpoints, leading to an inconsistent client experience.
      * **Poor Interoperability**: Cannot be understood generically by standard HTTP clients, libraries, or gateways that have built-in support for standard error formats.

### 2\. Standardized Error Schema (RFC 7807)

This approach involves adopting the IETF standard "Problem Details for HTTP APIs" (RFC 7807). This standard defines a simple, extensible JSON object for communicating error conditions.

  * **Core Fields**: `type`, `title`, `status`, `detail`, `instance`.
  * **Pros**:
      * **Industry Standard**: Promotes interoperability and eliminates guesswork for API consumers.
      * **Extensible**: The standard allows for adding custom, domain-specific members to the object.
      * **Self-Documenting**: The `type` field is a URI that can link directly to detailed documentation about the specific error, empowering developers to resolve issues independently.
  * **Cons**:
      * Requires a one-time effort to adopt the new standard and refactor existing custom error handling.

-----

## Decision

The ViolentUTF API will adopt **RFC 7807 "Problem Details for HTTP APIs"** as the exclusive standard for all client-facing error responses.

1.  **Standard Adherence**: All error responses will be `application/problem+json` and will conform to the RFC 7807 structure.
2.  **Custom Extensions**: The standard object will be extended with the following custom members for enhanced diagnostics and traceability:
      * `correlation_id`: The unique ID for the request, linking the error response directly to the detailed logs (as defined in ADR-008).
      * `error_code`: A short, stable, human-readable code for programmatic error handling on the client side.
3.  **Centralized Handling**: A global exception handling mechanism will be implemented in the FastAPI application to catch all exceptions and ensure they are consistently mapped to the standard RFC 7807 format.
4.  **No Information Leakage**: Stack traces and other internal debugging details will **never** be returned in API responses in production environments.

-----

## Rationale

Adopting RFC 7807 is a strategic decision to enhance the API's quality, security, and usability.

1.  **Improves Developer Experience**: A consistent, standard error format is predictable. This makes client-side error handling logic simpler, more robust, and less prone to breaking. The `type` URI provides a powerful mechanism for self-service documentation, drastically reducing the time developers spend trying to understand an error.

2.  **Enhances Diagnostics and Support**: By extending the standard to include our `correlation_id`, we create a seamless link between the error a user sees and the detailed, internal logs our developers and support teams can access. A user can report an error with a `correlation_id`, allowing us to instantly retrieve the full context of the failure without needing to ask for more information.

3.  **Secure by Default**: A centralized exception handler is a critical security control. It ensures that no matter what unexpected error occurs in the application, it is caught and mapped to a safe, generic, and standardized response. This prevents the accidental leakage of sensitive internal state or stack traces that could aid an attacker.

4.  **Promotes Professionalism and Interoperability**: Using an IETF standard signals a commitment to quality and best practices. It aligns the API with the broader ecosystem, making it easier to integrate with standard tooling, gateways, and client libraries that may have built-in support for RFC 7807.

-----

## Implementation Details

### Example RFC 7807 Error Response

The following is an example of a `400 Bad Request` validation error.

```json
{
  "type": "https://api.violentutf.gsa.gov/errors/validation-error",
  "title": "Validation Error",
  "status": 400,
  "detail": "One or more fields in the request body failed validation.",
  "instance": "/api/v1/scans",
  "correlation_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "error_code": "VUTF-1001",
  "invalid_params": [
    {
      "field": "scan_name",
      "reason": "must not be empty"
    },
    {
      "field": "target_model",
      "reason": "is not a valid model identifier"
    }
  ]
}
```

### Centralized Exception Handler

This will be implemented using FastAPI's `@app.exception_handler` decorator. A global handler will catch all `Exception` types, log the full internal error with its stack trace, and then return the sanitized, public-facing RFC 7807 response to the client.

### Error Dictionary

To ensure consistency, a central, version-controlled "Error Dictionary" will be created within the codebase. This registry will map internal application exceptions and `error_code` strings to their corresponding RFC 7807 `type` URI, `title`, and `status` code. This makes adding new, well-defined errors a simple and consistent process for all developers.

**Example Entry in Error Dictionary**:
`"VUTF-1001": { "status": 400, "title": "Validation Error", "type": "/errors/validation-error" }`

-----

## Consequences

  * **Positive**:

      * All API errors become predictable, consistent, and well-documented.
      * Client-side error handling logic is greatly simplified and more robust.
      * Debugging is streamlined by the direct link (`correlation_id`) between a user-facing error and internal logs.
      * The API's security posture is improved by preventing the leakage of internal implementation details.

  * **Negative**:

      * Requires a one-time engineering effort to implement the centralized handler and refactor any existing error logic.
      * Developers must adhere to the process of defining new errors in the central dictionary rather than creating one-off, inconsistent error responses.

  * **Technical Impact**:

      * A global exception handling middleware must be implemented in the FastAPI application.
      * The Error Dictionary must be created and maintained as a central source of truth for all error types.
      * All custom application exceptions should be designed to map cleanly to the standard error response model.

-----

## Related Artifacts/Decisions

  * **ADR-008: Structured JSON Logging**: The `correlation_id` defined in this ADR is the critical link between the error response sent to the client and the detailed, internal log entry containing the full context and stack trace.
