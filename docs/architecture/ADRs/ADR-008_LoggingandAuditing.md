# ADR-008: Structured JSON Logging for Multi-Tenant Auditing and Observability

## Status
Approved

## Authors
Tam Nguyen (Cybonto)

## Date
2025-07-27

## Stakeholders
* API Development Team
* Platform Operations Team
* Security and Compliance Team
* Incident Response Team

## Context
For a security platform like ViolentUTF, logging is a core security function, not merely a debugging tool. A comprehensive and immutable audit trail is essential for incident investigation, compliance, non-repudiation, and operational insight. Given the API's multi-tenant architecture, it is critical that every action can be securely and unambiguously attributed to a specific tenant (organization) and user.

As decided in ADR-007, the platform will use an asynchronous architecture with background workers, creating a distributed system. This necessitates a logging strategy that can trace a single logical operation across multiple processes and services.

Furthermore, this ADR establishes the application's logging strategy with the explicit goal of being **telemetry-agnostic**. The API will not be tightly coupled to a specific telemetry stack (e.g., ELK, Splunk, Datadog). Instead, it will produce a standardized, structured log output that can be easily ingested and processed by any modern log aggregation platform that may be adopted in the future.

---
## Considered Options

### 1. Unstructured Text Logging
This approach involves writing plain text, human-readable lines to log files or standard output. It is the simplest form of logging, often implemented with basic `print()` statements or a standard logging library's default configuration.

* **Pros**: Simple to implement.
* **Cons**: Brittle and nearly impossible for machines to parse reliably, making automated analysis and alerting ineffective. Fails completely in a distributed system. Insufficient for a reliable audit trail.
* **Verdict**: Unacceptable for a modern, scalable, and secure production application.

### 2. Structured JSON Logging
This approach involves treating every log event as a piece of data, emitting each entry as a self-contained, machine-readable JSON object. Each JSON object contains a consistent set of fields, including the message and rich contextual data.

* **Pros**: Easily ingested by any log aggregator, enables powerful querying and filtering, facilitates automated alerting, and can easily carry rich context.
* **Cons**: Can be slightly less pleasant for a human to read in its raw, single-line JSON format without a dedicated log viewer.
* **Verdict**: The only viable option for a robust, auditable system.

---
## Decision
The ViolentUTF API will adopt a comprehensive logging and auditing strategy based on the following principles:

1.  **Format**: All application logs will be emitted as **Structured JSON** objects.
2.  **Output**: The application will log to **standard output (`stdout`)** as a stream of JSON objects, following containerization best practices.
3.  **Context Enrichment**: Every log entry will be automatically enriched with contextual data, including a **Correlation ID** and **Multi-Tenant Identity** (`organization_id`, `user_id`).
4.  **Log Level Policy**: A formal policy will govern the use of log levels to ensure reliability and enable effective alerting.
5.  **Data Redaction**: A strict, centrally managed data redaction policy will be implemented to prevent sensitive data from being written to logs.

---

## Log Level Policy
To ensure logs are meaningful and actionable, the following semantics for log levels will be enforced. The default log level for production environments will be `INFO`.

* **DEBUG**: Granular information for developers during active troubleshooting. May include detailed diagnostic data. **Must not be enabled in production** except for brief, targeted debugging sessions on specific instances.
* **INFO**: Routine operational events. Records the normal, healthy execution of the application (e.g., `HTTP request received`, `Scan task started`, `User authenticated successfully`). These logs provide the general audit trail.
* **WARNING**: Indicates an unusual or unexpected event that does not (yet) affect the system's operation but may signify a potential problem. This is for events that should be reviewed by an operator. (e.g., `API key is nearing expiration`, `Database connection pool is reaching capacity`, `Retrying a failed operation`).
* **ERROR**: A significant failure occurred within a specific operation or request, but the application as a whole is still functional. The immediate request failed, but the service can still handle other requests. These events **must be investigated**. (e.g., `Failed to process job from queue`, `Unhandled exception in an API endpoint`).
* **CRITICAL**: The application has encountered a severe error that prevents it from functioning correctly and may require immediate intervention. This signifies a service-level failure. (e.g., `Cannot connect to the database`, `Message broker is unreachable`, `Failed to load critical configuration`). These events **must trigger an immediate page/alert** to the on-call team.

---
## Rationale

This decision establishes a secure, observable, and future-proof foundation for the platform's operational health.

1.  **Enables Auditing and Observability (Structured JSON)**: Structured logs are a prerequisite for the powerful querying, dashboarding, and alerting capabilities of any telemetry platform, enabling effective security auditing and operational monitoring.

2.  **Critical for Multi-Tenancy (Context Enrichment)**: Embedding the `organization_id` and `user_id` in every log record is the only reliable way to build a secure audit trail in a multi-tenant environment. It allows security teams to answer "who did what, to what, and when?" for any specific tenant.

3.  **Ensures Reliability (Log Level Policy)**: A formal log level policy makes our observability reliable. It ensures that `ERROR` and `CRITICAL` logs are meaningful signals of system health, allowing for the creation of high-fidelity, low-noise alerting systems.

4.  **Provides End-to-End Visibility (Correlation ID)**: A Correlation ID is the only mechanism that allows an engineer to trace a user's request from the initial API call through the message queue and into the specific background worker that processed it, which is essential for debugging our asynchronous system.

5.  **Secure by Design (Data Redaction)**: A formal policy of redacting sensitive data is a critical security control. It minimizes the risk that the logs themselves could become a high-value target for attackers.

6.  **Scalable and Portable (Logging to `stdout`)**: This decouples the application from the logging infrastructure. The application doesn't need to know if logs are sent to ELK, Splunk, or `/dev/null`. This makes the application highly scalable and portable, fulfilling the "telemetry-agnostic" requirement.

---
## Implementation Details

### Log Content and Schema
Every log entry will adhere to a standard base schema to ensure consistency.
* `timestamp`: (String) The event time in ISO 8601 format with UTC timezone.
* `level`: (String) The log severity (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).
* `message`: (String) The primary, human-readable log message.
* `correlation_id`: (String) The unique ID tracing the request through the system.
* `service_name`: (String) The name of the service emitting the log (e.g., `violentutf-api-web`, `violentutf-api-worker`).
* `auth_context`: (Object, optional) Contains identity information.
    * `organization_id`: (String) The UUID of the tenant.
    * `user_id`: (String) The UUID (`sub` claim) of the user.
* `http_context`: (Object, optional) For logs related to an HTTP request.
    * `method`: (String) e.g., `GET`, `POST`.
    * `path`: (String) The request path.
    * `status_code`: (Integer) The response status code.
    * `source_ip`: (String) The client's IP address.
* `extra_data`: (Object, optional) A container for any other structured key-value pairs relevant to the specific log event.

### Data Redaction Policy
A central redaction function will be applied to all structured log data before serialization. This function will redact fields based on key names. The list of redacted keys will include, but is not limited to:
* `password`, `token`, `secret`, `apiKey`, `credentials`
* `authorization` (for the HTTP header)
* `firstName`, `lastName`, `email` (any potential PII)
* Content of user-submitted prompts or model responses, which will be logged separately only when an explicit audit flag is enabled for a specific test.

### Performance and Scalability Considerations
While structured logging is essential, it can become a performance bottleneck under extreme load.
* The application's logging library will be configured for asynchronous log writing to avoid blocking the main application threads.
* For `DEBUG` level logging, which can be extremely verbose, **log sampling** may be implemented in the future. This would allow a small, statistically significant percentage of debug traces to be captured in production without incurring the full performance cost.

---
## Consequences

* **Positive**:
    * Creates a highly valuable, secure, and auditable data source for operations and security.
    * Drastically simplifies the process of debugging issues in a complex, distributed system.
    * The application is immediately compatible with any standard, enterprise-grade log aggregation platform.
    * The security posture is improved by providing a clear audit trail and preventing secret leakage into logs.
    * The reliability of the system is enhanced through meaningful, actionable alerts based on log levels.

* **Negative**:
    * Requires developer discipline to consistently use the structured logger and provide meaningful context.
    * There is a performance overhead associated with serializing JSON objects and enriching them with context, which must be monitored.

* **Technical Impact**:
    * A standard structured logging library (e.g., `structlog`) must be configured and used throughout the application.
    * A FastAPI middleware must be implemented to generate the Correlation ID and inject context into the logger for every request.
    * A central data redaction processor must be built.
    * The downstream logging infrastructure (the responsibility of the operations team) is now critical for observability and must be configured for secure log transport (e.g., TLS) and storage (e.g., encryption at rest).

---
## Related Artifacts/Decisions
* **ADR-002: Phased Authentication Strategy**: The authentication system provides the `organization_id` and `user_id` that are essential for the `auth_context` in every log.
* **ADR-007: Asynchronous Task Processing**: The distributed nature of the system is the primary driver for requiring Correlation IDs for end-to-end tracing.
* **ADR-011: Historical Code Analysis**: The logging patterns defined in this ADR are automatically monitored for compliance violations through the Historical Code Analysis tool, which detects non-structured logging, missing correlation IDs, and PII exposure in audit reports.
