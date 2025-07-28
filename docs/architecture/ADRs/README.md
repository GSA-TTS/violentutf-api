Of course. Here is a `README.md` file for the ADR folder.

---

# Architecture Decision Records

## Overview

This directory contains the official Architecture Decision Records (ADRs) for the standalone **ViolentUTF API** project. [cite_start]ADRs are essential instruments for our engineering process, providing clarity on significant architectural decisions, mitigating risk, and building a durable knowledge base that accelerates development and ensures long-term viability[cite: 5, 6].

Each record documents a single, architecturally significant decision, including the context that led to it, the options considered, and the consequences of the chosen path. [cite_start]This log serves as a vital communication and decision-tracking tool for all stakeholders[cite: 11].

---
## Status Definitions

Each ADR has a status indicating its current state in the decision lifecycle:
* **Proposed**: The decision is under consideration and open for discussion.
* **Accepted**: The decision has been approved and should be followed by the development team.
* **Deprecated**: The decision was previously accepted but is no longer recommended.
* **Superseded**: The decision has been replaced by a newer ADR.

---
## ADR Index

### Foundational Architecture
| ID | Title | Status | Date |
| :--- | :--- | :--- | :--- |
| ADR-001 | Adopt REST for Standalone API Endpoints | Accepted | 2025-07-27 |
| ADR-002 | Phased Authentication Strategy using JWT and API Keys | Accepted | 2025-07-27 |
| ADR-003 | Hybrid Authorization Model using RBAC and ABAC | Accepted | 2025-07-27 |
| ADR-004 | URI Path Versioning Strategy | Accepted | 2025-07-27 |
| ADR-005 | Multi-Layered Rate Limiting and Resource Consumption Policy | Accepted | 2025-07-27 |
| ADR-006 | JSON as the Exclusive Data Serialization Format | Accepted | 2025-07-27 |
| ADR-007 | Asynchronous Task Processing with HTTP Polling and Webhooks | Accepted | 2025-07-27 |
| ADR-008 | Structured JSON Logging for Multi-Tenant Auditing | Accepted | 2025-07-27 |
| ADR-009 | Standardized Error Handling with RFC 7807 | Accepted | 2025-07-27 |
| ADR-010 | Automated Dependency Management and SCA Policy | Accepted | 2025-07-27 |

### Feature Group Architecture
| ID | Title | Status | Date |
| :--- | :--- | :--- | :--- |
| ADR-F1.1 | Sandboxed Templating Engine for Attack Payloads | Accepted | 2025-07-27 |
| ADR-F1.2 | Server-Side Orchestration for Multi-Turn Attacks | Accepted | 2025-07-27 |
| ADR-F1.3 | Extensible Plugin Architecture for Target AI Integration | Accepted | 2025-07-27 |
| ADR-F2.1 | Database-Driven Vulnerability Taxonomy Model | Accepted | 2025-07-27 |
| ADR-F2.2 | Polyglot Persistence Strategy for Session Evidence | Proposed | 2025-07-27 |
| ADR-F3.1 | Hybrid Scoring Architecture for Model Risk Analysis | Accepted | 2025-07-27 |
| ADR-F3.2 | Server-Side Engine for Automated Report Generation | Accepted | 2025-07-27 |
| ADR-F4.1 | Container-based Sandboxing for Untrusted Model Execution | Proposed | 2025-07-27 |
| ADR-F4.2 | Centralized Secrets Management for Target System Credentials | Proposed | 2025-07-27 |

---
## Creating a New ADR

To propose a new architectural decision:
1.  Copy the `template_ADR_27JUL25.md` file to a new file named `ADR-XXX-decision-title.md`, where `XXX` is the next sequential number.
2.  Set the status to `Proposed`.
3.  Fill out the template with the relevant context, options, and rationale.
4.  Submit a pull request to the main branch for review and discussion with the team.
