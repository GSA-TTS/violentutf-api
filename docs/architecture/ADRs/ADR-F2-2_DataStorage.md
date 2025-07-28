Of course. Here is the next Architecture Decision Record in the feature series, focusing on the critical strategy for data storage.

***

# ADR-F2.2: Polyglot Persistence Strategy for Session Evidence

## Status
Proposed

## Authors
Tam Nguyen (Cybonto)

## Date
2025-07-27

## Stakeholders
* API Development Team
* Platform Operations Team
* Data Engineering Team
* Cloud Infrastructure and Cost Management Team
* GSA Compliance and Security Team

## Context
The core function of the ViolentUTF platform is to generate and analyze data from red teaming sessions. This data is characterized by several competing demands:
* **Volume**: A single test run can generate thousands or millions of individual prompt-response pairs.
* **Variety**: The data is diverse, ranging from highly structured metadata (users, test configurations) to semi-structured evidence (prompt/response/score documents) and large, unstructured artifacts (raw logs, reports).
* **Sensitivity**: This data contains direct evidence of exploitable vulnerabilities in customer systems and is therefore extremely sensitive.
* **Access Patterns**: Different data types require different access patterns. Core metadata requires strong transactional consistency, while test evidence requires high-throughput writes and flexible queries.

This "data gravity" problem makes it highly unlikely that a single type of data store (a "monolithic persistence" strategy) can efficiently satisfy all these requirements for performance, cost, and scalability.

---
## Considered Options

### 1. Relational Database Only (e.g., PostgreSQL)
This approach involves storing all platform data—users, configurations, and every individual prompt/response pair—in a single relational database.

* **Pros**:
    * Provides strong ACID guarantees and transactional integrity for all data.
    * Simplest approach from a data access perspective, as the application only needs to talk to one database.
* **Cons**:
    * **Poor Scalability for Evidence**: Relational databases are not optimized for ingesting massive volumes of semi-structured text data and can become a performance bottleneck.
    * **High Cost**: Storing terabytes of text-heavy evidence data in a high-performance relational database is prohibitively expensive.
    * **Schema Rigidity**: The rigid schema makes it difficult to adapt to new types of metadata that may be generated in future tests.

### 2. Document Database Only (e.g., MongoDB)
This approach involves storing all platform data, including user and configuration metadata, in a document database.

* **Pros**:
    * Excellent for storing the semi-structured test evidence, offering high write throughput and a flexible schema.
* **Cons**:
    * **Lacks Transactional Integrity**: Does not provide the same strong, multi-record transactional guarantees as a relational database, which is a risk for critical metadata like user accounts or billing information.
    * **Inefficient for Relational Queries**: Handling complex relationships and joins, which are common for application metadata, is less efficient than in a SQL database.

### 3. Polyglot Persistence (Hybrid Approach)
This approach uses multiple, specialized data stores, choosing the right tool for each specific job. Data is partitioned across different storage systems based on its structure and access requirements.

* **Pros**:
    * **Optimized for Performance, Cost, and Scale**: Each data type is stored in a system designed for it, leading to the best possible outcome for all three factors.
    * **Enables Best-of-Breed Technology**: Allows the platform to leverage the specific strengths of relational, document, and other database types.
* **Cons**:
    * **Increased Architectural Complexity**: The application must be designed to interact with multiple data systems, which is more complex than a single data access layer.
    * **Data Consistency Challenges**: Maintaining consistency across different data stores (e.g., ensuring a summary record in PostgreSQL corresponds to evidence in MongoDB) requires careful application-level logic.

---
## Decision
The ViolentUTF platform will adopt a **Polyglot Persistence strategy** for its data storage architecture. Data will be partitioned across three distinct types of storage systems.

1.  **Relational Database (e.g., PostgreSQL)**: This will be the **system of record for all highly structured metadata**. This includes, but is not limited to: user accounts, organizations, API keys, test configurations, orchestrator definitions, the vulnerability taxonomy (from ADR-F2.1), and high-level summaries of test sessions.
2.  **Document Database (e.g., MongoDB or DynamoDB)**: This will be the **primary store for high-volume, semi-structured test evidence**. Each individual prompt-response-score-classification set will be stored as a single document. This is the "hot" storage for recent and active test data.
3.  **Blob Storage (e.g., AWS S3 or Google Cloud Storage)**: This will be used for **cost-effective, long-term archival** of large, raw artifacts. This includes full, verbose conversation logs, user-uploaded datasets, and generated PDF reports.

---
## Rationale

This hybrid strategy is the only approach that effectively addresses the conflicting requirements of the platform's data.

1.  **Optimizes for Cost and Performance**: This is the primary driver. Using a document database for high-volume evidence writes and blob storage for cheap archival is orders of magnitude more cost-effective and performant than forcing everything into an expensive, high-performance relational database. It ensures we are always using the right, most efficient tool for each data type.

2.  **Ensures Both Scalability and Integrity**: The architecture allows each component to scale independently based on its specific load. We can scale the document database cluster to handle a massive influx of test evidence without impacting the core transactional relational database. This provides scalability where needed, while the relational database continues to provide the non-negotiable ACID guarantees for critical application metadata.

3.  **Provides Schema Flexibility Where It Matters**: Test evidence is likely to evolve. New scoring models or metadata fields will be added over time. The flexible, document-based schema for evidence accommodates these changes easily, without requiring complex and risky database migrations on a massive table.

---
## Implementation Details

### Data Partitioning Example
* **PostgreSQL (`transactional_db`)**:
    * Tables: `users`, `organizations`, `test_configurations`, `vulnerability_taxonomies`, `session_summaries`
* **MongoDB (`evidence_db`)**:
    * Collection: `session_evidence`
    * Document Structure: `{ "session_id": ..., "prompt": { ... }, "response": { ... }, "scores": [ ... ], "vulnerability_ids": [ ... ] }`
* **S3 / Blob Storage**:
    * Buckets: `raw-session-logs/`, `user-uploads/`, `generated-reports/`, `archived-evidence/`

### Data Lifecycle Management
To manage costs and comply with data retention policies, a formal data lifecycle will be implemented.
* **Hot Storage (0-90 days)**: Detailed test evidence resides in the Document Database, where it is actively and quickly queryable for recent test analysis.
* **Cold Storage (90 days - 7 years)**: A scheduled, automated background process will archive evidence documents from the Document Database into a compressed format (e.g., `JSONL.gz`) and move them to a low-cost archival tier in Blob Storage.
* **Deletion (> 7 years)**: A data retention policy will be enforced to permanently delete archived data after a defined period (e.g., 7 years), subject to customer and legal requirements. The high-level summary record in the relational database may be kept longer.

---
## Consequences

* **Positive**:
    * The data architecture is highly scalable, performant, and cost-optimized.
    * The platform can ingest massive volumes of test data without degrading the performance of core application functions.
    * The use of a flexible schema for evidence makes the platform adaptable to future changes.

* **Negative**:
    * **Increased Architectural Complexity**: This is the primary trade-off. The application must interact with multiple data systems, and developers need to be proficient with each.
    * **New Consistency Challenges**: The application logic is now responsible for ensuring data consistency across the different stores (e.g., through retry mechanisms or two-phase commits at the application level).
    * **Increased Operational Burden**: The operations team is now responsible for deploying, monitoring, backing up, and maintaining multiple types of database systems.

* **Technical Impact**:
    * The application's data access layer must be designed to abstract interactions with the different data stores.
    * An automated background process (e.g., a scheduled Celery task) must be built to handle the data archiving and lifecycle management.
    * End-to-end testing must now validate data consistency across the polyglot persistence landscape.

---
## Related Artifacts/Decisions
* **ADR-F2.1: Data Model for Vulnerability Taxonomies**: The taxonomy data defined in this ADR will reside in the relational database, and its primary keys will be referenced in the evidence documents stored in the document database.
* **ADR-F3.1: Model Safety, Bias, and Risk Scoring Architecture**: The scoring engine will read evidence from the document database and write its summary findings to the relational database.
