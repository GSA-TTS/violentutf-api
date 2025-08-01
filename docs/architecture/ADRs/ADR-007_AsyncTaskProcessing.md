# ADR-007: Asynchronous Task Processing with HTTP Polling and Webhooks

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
A core function of the ViolentUTF API is to initiate computationally expensive and long-running tasks, such as executing a PyRIT orchestrator or running a comprehensive Garak security scan. These operations can take anywhere from seconds to many minutes, or even hours, to complete.

Attempting to handle these tasks within a standard, synchronous HTTP request-response cycle is not feasible. This approach would lead to blocked clients, request timeouts, poor reliability, and an inability to scale. A robust, asynchronous processing model is required to ensure the API is responsive, reliable, and provides a good developer experience for clients initiating these tasks. The solution must provide a clear and consistent way for a client to start a task, track its progress, and retrieve the results upon completion.

---
## Considered Options

### 1. Synchronous Request/Response (Anti-Pattern)
The client sends a request and the HTTP connection is held open until the task is complete and the final result is returned in the response.

* **Pros**: Simple for the client to implement.
* **Cons**:
    * **Unreliable**: Guaranteed to fail for any task that exceeds the timeout limits of clients, load balancers, and web servers (typically 30-120 seconds).
    * **Poor Scalability**: Ties up server resources and connection pools for long periods, severely limiting the number of concurrent tasks the API can handle.
    * **Verdict**: Fundamentally unsuitable for this API's core use case.

### 2. HTTP Polling (Asynchronous Request-Reply)
The client initiates a task, and the server immediately responds with `202 Accepted`, providing a unique URL to a status resource. The client then periodically polls this status URL until the task is marked as complete, at which point the response includes a link to the final result.

* **Pros**:
    * RESTful and stateless, using standard HTTP semantics.
    * Simple for any client to implement (even basic shell scripts).
    * Decouples the client from the task execution, making the system resilient.
* **Cons**:
    * Can be inefficient, as the client may make many polling requests before the task is finished.
    * There is a delay between task completion and the client discovering it on the next poll.

### 3. WebSockets
The client establishes a persistent, bidirectional connection with the server. After initiating a task, the server can push real-time status updates and the final result back to the client over this connection.

* **Pros**:
    * Highly efficient for real-time updates with minimal latency.
* **Cons**:
    * **Stateful**: Introduces significant server-side complexity in managing persistent connections.
    * **Complex to Scale**: Requires special configuration for load balancers (e.g., sticky sessions) and can be more difficult to scale horizontally than stateless HTTP.
    * **Overkill**: The complexity may be unnecessary when many clients simply need to know when a job is done, not receive a continuous stream of updates.

### 4. Webhooks
After the client initiates a task, it provides a callback URL. The server's backend system makes a `POST` request to this client-provided URL once the task is complete, delivering the result directly.

* **Pros**:
    * Extremely efficient, as it eliminates polling entirely.
* **Cons**:
    * **High Client-Side Burden**: Requires the client to be a server itself, capable of receiving incoming HTTP requests from the internet.
    * **Security and Network Challenges**: The client's endpoint must be publicly accessible, which is often not feasible or secure for scripts, internal systems, or web applications running behind a firewall.

---
## Decision
The ViolentUTF API will implement a **comprehensive asynchronous task processing architecture** that combines a backend task queue with a hybrid client-facing model.

1.  **Backend Architecture**: All long-running tasks will be offloaded to a dedicated **Task Queue system** (e.g., Celery) with a message broker (e.g., Redis). This decouples task execution from the API web server.

2.  **Primary Client Mechanism: HTTP Polling**: The default and universally supported method for tracking tasks will be **HTTP Polling**. All long-running endpoints will immediately return a `202 Accepted` response with a status URL.

3.  **Secondary Client Mechanism: Webhooks**: As an optional, advanced feature for sophisticated clients, the API will also support **Webhooks**. A client can provide a `webhook_url` in the initial request to receive a callback with the final result, bypassing the need to poll.

---
## Rationale

This hybrid approach provides the best combination of reliability, scalability, and developer experience.

1.  **Core Reliability and Scalability**: Implementing a backend task queue is the only professional-grade solution for handling long-running jobs. It makes the API responsive and allows the task processing system (the workers) to be scaled independently of the web-facing API servers, ensuring the system is both resilient and performant.

2.  **A Universal Solution for All Clients**: By making HTTP Polling the default mechanism, we ensure that *any* client, no matter how simple, can successfully use the API's core features. It is a robust, stateless, and easy-to-understand pattern that serves as an excellent baseline.

3.  **Efficiency for Advanced Users**: Offering Webhooks as an optional enhancement provides a more efficient, "push"-based alternative for advanced server-to-server integrations. This demonstrates a commitment to a superior developer experience by catering to different client capabilities without imposing the most complex pattern on everyone. This dual-pattern approach offers maximum flexibility.

4.  **Avoiding Unnecessary Complexity**: We are explicitly choosing *not* to use WebSockets as the primary mechanism to avoid the significant operational and scaling complexities associated with managing stateful, persistent connections for a general-purpose API.

---
## Implementation Details

* **Backend Architecture**:
    * **Web Server (FastAPI)**: Receives the initial request, validates it, creates a task record in the database with a `PENDING` status, and pushes a job onto the task queue.
    * **Message Broker (Redis)**: Manages the queue of jobs to be processed.
    * **Worker (Celery)**: Separate processes that pull jobs from the queue, execute the long-running task (e.g., run a Garak scan), and update the task record with the final status and result location.

* **API Flow (HTTP Polling)**:
    1.  Client: `POST /api/v1/scans`
    2.  Server: Responds immediately with `202 Accepted` and a body: `{ "task_id": "uuid-123", "status_url": "/api/v1/tasks/uuid-123" }`
    3.  Client: Periodically `GET /api/v1/tasks/uuid-123`
    4.  Server: Responds with `200 OK` and `{ "task_id": "uuid-123", "status": "RUNNING" }`
    5.  When complete, Server: Responds to the `GET` request with `200 OK` and `{ "task_id": "uuid-123", "status": "SUCCESS", "result_url": "/api/v1/scans/results/uuid-abc" }`
    6.  Client: `GET /api/v1/scans/results/uuid-abc` to retrieve the final result.

* **API Flow (Webhooks)**:
    1.  Client: `POST /api/v1/scans` with a body including `{ ..., "webhook_url": "https://my-service.com/callback", "webhook_secret": "secure-string" }` <!-- pragma: allowlist secret -->
    2.  Server: Responds immediately with `202 Accepted`.
    3.  When the task completes, a worker process makes a `POST` request to `https://my-service.com/callback` with the result data. The request will be signed with the provided secret (e.g., in an `X-Signature` header) so the client can verify its authenticity.

---
## Consequences

* **Positive**:
    * The API will be highly scalable and resilient. A flood of task requests will not crash the web servers.
    * The client experience is non-blocking and predictable.
    * The system can support a wide variety of clients, from simple scripts to sophisticated backend services.

* **Negative**:
    * This introduces significant architectural complexity and new infrastructure components (a message broker and a fleet of worker processes) that must be deployed, scaled, and monitored.
    * The logic for client applications is inherently more complex than a simple synchronous call.
    * End-to-end testing becomes more complicated, as it must verify the behavior of the web server, broker, and workers.

* **Technical Impact**:
    * Requires the development of a standardized task management library within the application.
    * All long-running endpoints must be refactored to conform to this asynchronous pattern.
    * The operations team is now responsible for a distributed system with more moving parts.

---
## Related Artifacts/Decisions
* This decision directly impacts the design and implementation of nearly all action-oriented endpoints, particularly those defined in `endpoints.md` for orchestrator execution and Garak probes.
