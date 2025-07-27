Of course. Here is the next Architecture Decision Record in the feature series, focusing on the critical security architecture for interacting with untrusted models.

***

# ADR-F4.1: Container-based Sandboxing for Untrusted Model Execution

## Status
Proposed

## Authors
Tam Nguyen (Cybonto)

## Date
2025-07-27

## Stakeholders
* API Development Team
* Platform Operations Team
* Security and Compliance Team
* GSA Compliance and Security Team

## Context
To maximize its utility, the ViolentUTF platform must be able to test not only well-known commercial AI models via their trusted APIs, but also a wide range of user-provided, self-hosted, and open-source models (e.g., from sources like Hugging Face). These third-party models often come with their own custom Python code for loading weights and running inference.

Executing this arbitrary, untrusted code directly within the platform's core application processes represents an unacceptable security risk. A malicious model's loading script could contain code designed to read sensitive data, attack other services, or escape its environment, leading to a complete compromise of the platform and all tenant data. Therefore, a strong sandboxing architecture is required to execute this untrusted code in a securely isolated environment.

---
## Considered Options

### 1. Direct In-Process Execution
This approach involves loading and running the untrusted model code directly within the same Python process as our main application workers.

* **Pros**:
    * Simple to implement.
* **Cons**:
    * **Catastrophic Security Vulnerability**: This is the equivalent of granting every user who submits a model remote code execution (RCE) privileges on our backend servers. It is not a viable option.
    * **No Resource Isolation**: A poorly written model could consume all available CPU or memory, causing a Denial-of-Service that affects all other platform operations.
    * **Verdict**: Unacceptable and fundamentally insecure.

### 2. Container-based Sandboxing (e.g., Docker)
This approach involves provisioning a new, temporary, and highly restricted Docker container for each interaction with an untrusted model. The untrusted code runs inside this isolated container, which has its own process space, filesystem, and network stack.

* **Pros**:
    * **Strong, Industry-Standard Isolation**: Provides a robust security boundary using mature, battle-tested Linux kernel features (namespaces, cgroups).
    * **Pragmatic and Manageable**: Leverages a well-understood ecosystem (Docker, Kubernetes) that operations teams are familiar with, balancing high security with operational feasibility.
    * **Fine-Grained Resource Control**: Allows for precise limits on the CPU, memory, and I/O that the untrusted code can consume.
* **Cons**:
    * **"Cold Start" Latency**: There is a performance overhead to provisioning a new container for each job.

### 3. MicroVM-based Sandboxing (e.g., Firecracker)
This approach involves provisioning an extremely lightweight virtual machine (a MicroVM) for each execution. This provides an even stronger, hardware-level virtualization boundary.

* **Pros**:
    * **Maximum Security Isolation**: Offers the strongest possible security boundary, as used by services like AWS Lambda.
* **Cons**:
    * **High Operational Complexity**: Requires more specialized infrastructure and operational expertise to manage compared to containers.
    * **Potentially Slower**: While very fast, cold start times can still be higher than for containers, and the ecosystem is less mature for general-purpose use.

---
## Decision
The ViolentUTF platform will use **Container-based Sandboxing** as the mandatory architecture for executing any untrusted code associated with a target AI model.

1.  **Ephemeral Containers**: For each execution against an untrusted model, a **new, ephemeral, single-use Docker container** will be provisioned on-demand. This container will be destroyed immediately after the execution is complete.
2.  **Highly Restrictive Security Profile**: Every sandbox container will be launched with a "secure by default" profile, including:
    * Execution as a non-root user.
    * A read-only root filesystem.
    * Dropping all unnecessary Linux kernel capabilities.
    * No network access by default.
3.  **Controlled Communication**: All communication between the platform's main orchestration worker and the sandboxed container will occur over a controlled and limited channel, such as standard input/output streams, not a general-purpose network connection.

---
## Rationale

This decision provides the best pragmatic balance of high security, operational feasibility, and platform flexibility.

1.  **Provides Strong and Defensible Security**: Containerization is the industry standard for application isolation. It effectively isolates the untrusted code's process space, filesystem, and network from the host system and from other tenants' sandboxes. This robust boundary is a necessary and sufficient control to mitigate the risk of RCE and lateral movement.

2.  **Balances Security with Operational Pragmatism**: While MicroVMs offer a theoretically stronger boundary, they also introduce significant operational complexity. Container technology is mature, well-understood, and easily managed by standard orchestration tools like Kubernetes. This approach delivers a very high level of security without demanding a radical shift in our operational model.

3.  **Unlocks Critical Platform Extensibility**: This sandboxing architecture is a key enabler for a major platform feature: the ability to safely test any model. This dramatically increases the value and applicability of the platform for users who work with custom or fine-tuned open-source models.

4.  **Protects Platform Stability**: By enforcing strict resource limits (CPU, memory) on each container, we protect the host system and the overall platform from resource exhaustion attacks or poorly optimized model code, ensuring the reliability of the service for all users.

---
## Implementation Details

### Execution Flow
1.  An orchestration worker receives a job to test an untrusted model.
2.  The worker uses a container management SDK (e.g., Docker SDK for Python) to launch a new, sandboxed container from a pre-built, minimal base image.
3.  The untrusted model code and the specific prompt for the test are passed into the container via `stdin` or a temporary, isolated volume mount.
4.  The worker starts the execution script inside the container.
5.  The model's response is captured by reading the container's `stdout`. Any errors are read from `stderr`.
6.  Upon completion or timeout, the container and any associated volumes are **irrevocably destroyed**. No state is ever reused between executions.

### Secure Container Profile
All sandbox containers will be launched with a profile that includes these (or equivalent) settings:
* `--user=<non-root-uid>`: Run the process as a dedicated, unprivileged user.
* `--read-only`: Mount the container's root filesystem as read-only.
* `--cap-drop=ALL --security-opt=no-new-privileges`: Drop all Linux capabilities and prevent privilege escalation.
* `--network=none`: Disable all networking by default.
* `--memory=<limit> --cpus=<limit>`: Enforce strict resource limits.

---
## Consequences

* **Positive**:
    * The platform can now safely support a vast range of third-party and custom models, which is a major feature enhancement.
    * The critical security risk of Remote Code Execution from untrusted models is effectively mitigated.
    * The platform's overall security posture is significantly strengthened and is more easily auditable.

* **Negative**:
    * Introduces a "cold start" latency for each execution of an untrusted model due to the time required to provision the container.
    * Increases the performance and resource overhead on the worker nodes that are responsible for managing the container lifecycle.
    * This model is best suited for batch-based testing of untrusted models, not low-latency interactive use.

* **Technical Impact**:
    * Introduces a new, critical dependency on a container runtime (e.g., Docker) being available on all worker nodes.
    * The orchestration worker logic becomes significantly more complex, as it must now manage the full lifecycle of these sandboxed containers.
    * A hardened, minimal base container image must be built and maintained for the sandbox environment.

---
## Related Artifacts/Decisions
* This ADR provides the secure execution environment for the provider plugins defined in **ADR-F1.3 (Integration Architecture)**, specifically for plugins that are not simple API clients but require the execution of local, untrusted code.
* The sandboxing of untrusted code is a core component of the platform's overall security strategy, complementing **ADR-010 (Dependency Management)** which secures the platform's own code.
