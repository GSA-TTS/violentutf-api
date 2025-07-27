Of course. Here is the next Architecture Decision Record for the standalone ViolentUTF API, focusing on the rate limiting and resource consumption policy.

***

# ADR-005: Multi-Layered Rate Limiting and Resource Consumption Policy

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
As a standalone service, the ViolentUTF API is directly exposed to network traffic. The API executes resource-intensive and computationally expensive tasks, such as initiating large-scale security scans or generating complex reports. This makes it a prime target for both malicious Denial-of-Service (DoS) attacks and unintentional resource exhaustion from poorly configured client scripts.

Previously, this protection was handled by the APISIX gateway. As part of the spinoff, this responsibility must be implemented directly within the application to ensure its stability, availability, and security. A robust rate-limiting and resource consumption policy is a critical defense for ensuring fair use among tenants, controlling operational costs, and mitigating the following OWASP API Security risks:
* **API4:2023 - Unrestricted Resource Consumption**
* **API6:2023 - Unrestricted Access to Sensitive Business Flows**

---
## Considered Options

### 1. Token Bucket Algorithm
A flexible and widely used algorithm. Each client has a "bucket" of tokens that refills at a constant rate. Each API request consumes one or more tokens. This allows for short bursts of traffic up to the bucket's capacity while enforcing an average rate over time.

* **Pros**: Highly flexible, allows for legitimate traffic bursts, and is efficient to implement.
* **Cons**: Can be slightly more complex to implement than a fixed window.

### 2. Leaky Bucket Algorithm
This algorithm enforces a more rigid output rate. Incoming requests are added to a queue (the bucket), which is processed at a fixed, constant rate. If the queue is full, new requests are rejected.

* **Pros**: Excellent at smoothing out traffic into a steady stream.
* **Cons**: Punitive to clients that have legitimate needs for short bursts of requests, which can harm the user experience.

### 3. Fixed Window Counter Algorithm
The simplest method. It counts the number of requests from a client within a fixed time window (e.g., 1000 requests per hour).

* **Pros**: Very easy to implement.
* **Cons**: Flawed at the boundaries of the time window. A client can use their entire quota at the end of one window and immediately use the next quota at the beginning of the next, resulting in a traffic burst of up to twice the allowed rate.

### 4. Sliding Window Log Algorithm
The most accurate method. It stores a timestamp for each request in a log and counts the number of requests within the last time slice (e.g., the last hour).

* **Pros**: Perfectly enforces the rate limit without the boundary issues of the fixed window.
* **Cons**: High resource consumption, as it requires storing a timestamp for every single request, which can be costly and impact performance at scale.

---
## Decision
The ViolentUTF API will implement a **multi-layered rate limiting policy** based on the **Token Bucket algorithm**.

1.  **Core Algorithm**: The Token Bucket algorithm will be used for its balance of protection and flexibility.
2.  **State Management**: The state for the rate limiter (e.g., token counts for each principal) will be stored in a centralized, high-performance in-memory cache (**Redis**) to ensure consistency and performance across horizontally scaled API instances.
3.  **Layered Policy**: A multi-layered policy will be enforced, applying different limits to different classes of endpoints to provide targeted protection.
4.  **Client Communication**: The API will communicate rate limit status to clients via standard HTTP headers in every response.

---
## Rationale

This approach was chosen to provide robust, scalable, and intelligent protection for the API.

1.  **Flexibility for Clients (Token Bucket)**: The Token Bucket algorithm is the superior choice for this API's use case. It prevents sustained abuse while still accommodating legitimate client needs for short, high-traffic bursts (e.g., submitting a batch of prompts). This provides a better and less frustrating developer experience compared to the rigidness of a Leaky Bucket.

2.  **Defense-in-Depth (Layered Policy)**: A single global rate limit is insufficient. Some API endpoints (like starting a scan) are orders of magnitude more expensive than others (like fetching status). The multi-layered policy provides granular, defense-in-depth protection where it is needed most, directly mitigating the risk of costly resource consumption on sensitive business flows.

3.  **Scalability and Consistency (Redis)**: For the API to be stateless and horizontally scalable, the rate-limiting state cannot be stored in the memory of a single application instance. Using a shared, external cache like Redis is the industry-standard solution. It guarantees that the rate limit is enforced correctly and consistently, no matter how many API server instances are running.

4.  **Transparency and Good Practice (HTTP Headers)**: A well-behaved API should inform its clients of the rules. By returning headers like `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset`, we empower client developers to build more resilient and respectful integrations, reducing the likelihood they will hit the rate limit in the first place.

---
## Implementation Details

* **Rate Limit Principal**: Limits will be applied on a per-organization basis. The key for the rate limiter will be the `organization_id` extracted from the authenticated JWT (as defined in ADR-002), or a derivative of the authenticated API Key.

* **Policy Layers**: A multi-tiered policy will be implemented with distinct limits. The following are illustrative examples:
    * **Layer 1: General Access**: A high-level limit for all API requests per organization.
        * *Example*: 2000 requests per minute.
    * **Layer 2: Resource-Intensive Endpoints**: A much stricter limit on specific, costly operations.
        * *Example*: 10 requests per minute for `POST /api/v1/scans`.
        * *Example*: 20 requests per minute for `POST /api/v1/reports/generate`.
    * **Layer 3: Authentication Endpoints**: A strict limit based on source IP address to prevent credential-stuffing attacks.
        * *Example*: 5 requests per minute for `POST /api/v1/auth/token` per IP.

* **Client Response**:
    * **Headers**: Every API response will include the following HTTP headers:
        * `X-RateLimit-Limit`: The maximum number of requests allowed in the time window.
        * `X-RateLimit-Remaining`: The number of requests remaining in the current window.
        * `X-RateLimit-Reset`: The Unix timestamp indicating when the window resets.
    * **Error Response**: When a limit is exceeded, the API will return a `429 Too Many Requests` status code. The response may also include a `Retry-After` header indicating how many seconds the client should wait before trying again.

---
## Consequences

* **Positive**:
    * Significantly improves the stability, availability, and security of the API.
    * Ensures fair use of resources among all tenants on the platform.
    * Protects the platform from incurring runaway operational costs due to abuse.
    * Provides clear feedback to clients, enabling them to build more robust applications.

* **Negative**:
    * Introduces a new, critical runtime dependency on an external service (Redis).
    * Adds a small amount of latency to every API request to perform the rate-limiting check.
    * Requires careful configuration and management of the rate-limiting policies to avoid unduly blocking legitimate traffic.

* **Technical Impact**:
    * Requires the integration of a Redis client library into the application.
    * Requires the development of a flexible middleware that can apply different rate-limiting policies based on the request's endpoint and the principal's identity.
    * The operational team must now deploy, monitor, and maintain a highly available Redis cluster.

---
## Related Artifacts/Decisions
* **ADR-002: Phased Authentication Strategy using JWT and API Keys**: The rate limiting system relies on the principal identity (`organization_id`, API key) established by the authentication model to track requests.
