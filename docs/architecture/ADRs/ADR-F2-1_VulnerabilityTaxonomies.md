# ADR-F2.1: Database-Driven Vulnerability Taxonomy Model

## Status
Accepted

## Authors
Tam Nguyen (Cybonto)

## Date
2025-07-27

## Stakeholders
* API Development Team
* Security Researchers and Red Teamers (Primary Users)
* Security Content Team
* GSA Compliance and Security Team

## Context
For the results of the AI red teaming platform to be meaningful and actionable, they must be classified in a clear, consistent, and structured manner. Simply reporting that a "test failed" is insufficient. The platform needs a robust system—a taxonomy—to categorize detected vulnerabilities, ideally aligning with industry-standard frameworks like the OWASP Top 10 for Large Language Model Applications or MITRE ATLAS.

The landscape of AI attacks is evolving at an unprecedented pace. New techniques for prompt injection, data leakage, and model manipulation emerge constantly. Therefore, the platform's vulnerability taxonomy cannot be static; it must be a living system that can be updated easily and rapidly to reflect the current threat landscape.

---
## Considered Options

### 1. Hard-coded Enum
This approach involves implementing the vulnerability types as a fixed list (an enumeration) directly in the application's source code.

* **Pros**:
    * Very simple to implement initially.
* **Cons**:
    * **Extremely Brittle and Inflexible**: When a new class of AI attack emerges, adding it to the taxonomy would require a code change, a full test cycle, a new build, and a redeployment of the entire service.
    * **Fails the Extensibility Mandate**: This approach would cause the platform's knowledge base to become obsolete almost immediately, failing a core requirement to be adaptable.

### 2. Database-Driven Taxonomy
This approach involves designing a flexible data model for vulnerabilities and storing the taxonomy itself as data within the application's database.

* **Pros**:
    * **Highly Flexible and Future-Proof**: Administrators or a dedicated security content team can define new vulnerability types, create custom categories, and map them to industry standards by simply adding new rows to a database table. No code changes are required.
    * **Enables Dynamic Content**: The platform can adapt to the evolving threat landscape in real time.
    * **Supports Rich Data**: Allows for storing detailed descriptions, remediation advice, and other rich metadata associated with each vulnerability type.

---
## Decision
The ViolentUTF API will implement a **Database-Driven Vulnerability Taxonomy**.

1.  **Data-Driven Model**: The definitions, categories, and details of all supported vulnerabilities will be stored as data in a dedicated set of database tables, not as code.
2.  **Hierarchical Structure**: The data model will support a hierarchical (tree) structure, allowing for broad parent categories (e.g., "Sensitive Information Disclosure") with more specific child vulnerabilities (e.g., "PII Leakage," "Credential Leakage").
3.  **Industry Standard Mapping**: The schema will include a mechanism for mapping the platform's internal vulnerability definitions to one or more external, industry-standard frameworks (e.g., OWASP, MITRE).

---
## Rationale

This decision establishes a flexible and future-proof foundation for how the platform classifies and understands risk.

1.  **Adaptability to Evolving Threats**: This is the primary driver. A database-driven taxonomy allows the platform's knowledge base to be a living system, updated dynamically by administrators as new AI attack vectors are discovered. This ensures the platform remains relevant and effective without constant engineering intervention and redeployments.

2.  **Enables Rich and Consistent Reporting**: A structured, centralized taxonomy ensures that all platform outputs—from API responses to generated reports—use consistent, well-defined terminology. This makes the results clearer, more professional, and more valuable to users.

3.  **Facilitates Integration and Broader Communication**: By mapping internal classifications to industry standards like the OWASP Top 10 for LLMs, the platform's findings become instantly recognizable and useful within a customer's broader security program. This data can be more easily ingested by GRC (Governance, Risk, and Compliance) tools and communicated to stakeholders.

4.  **Foundation for Advanced Analytics**: A well-structured taxonomy is a prerequisite for future analytical features. It will allow the platform to perform trend analysis (e.g., "Is our new model more or less susceptible to prompt injection than the last version?") and provide deeper insights into an organization's AI risk posture.

---
## Implementation Details

### Proposed Database Schema
A new table, `vulnerability_taxonomies`, will be created to store the classification data. A second table, `taxonomy_mappings`, will handle links to external frameworks.

**`vulnerability_taxonomies` Table:**
* `id` (UUID, Primary Key): Unique identifier for the taxonomy entry.
* `name` (String, Not Null): The short, human-readable name of the vulnerability (e.g., "Prompt Injection").
* `description` (Text, Not Null): A detailed explanation of the vulnerability, what it is, and why it is a risk.
* `remediation_advice` (Text, Nullable): General guidance on how to mitigate this class of vulnerability.
* `parent_id` (UUID, Foreign Key to `vulnerability_taxonomies.id`, Nullable): A self-referencing key to create the hierarchy. `NULL` for top-level categories.
* `default_severity` (Enum, Not Null): The default severity rating (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

**`taxonomy_mappings` Table:**
* `id` (Integer, Primary Key)
* `taxonomy_id` (UUID, Foreign Key to `vulnerability_taxonomies.id`, Not Null): Links to the internal taxonomy entry.
* `framework_name` (String, Not Null): The name of the external standard (e.g., "OWASP LLM Top 10").
* `framework_id` (String, Not Null): The identifier within that framework (e.g., "LLM01").
* `framework_url` (String, Nullable): A direct link to the definition in the external standard.

### Initial Data Seeding
Upon deployment, the `vulnerability_taxonomies` table will be seeded with an initial set of definitions based on the current OWASP Top 10 for Large Language Model Applications to provide immediate value.

---
## Consequences

* **Positive**:
    * The platform's security intelligence can be updated without any code changes or service downtime.
    * All reporting and analysis will be based on a consistent, centrally managed source of truth.
    * The platform's findings are more valuable and easier to integrate into customers' existing security programs.

* **Negative**:
    * Adds complexity to the database schema and application logic.
    * Creates a new content management responsibility; the taxonomy must be actively maintained by a security content team to remain current.
    * An administrative UI or process will eventually be needed to manage the taxonomy data easily.

* **Technical Impact**:
    * Requires the creation of new database tables, models, and repositories.
    * The services responsible for scoring and reporting test results must be modified to query these new tables to classify their findings.
    * A data migration or seeding script is required to populate the initial taxonomy.

---
## Related Artifacts/Decisions
* This decision heavily influences **ADR-F2.2: Evidence and Red Teaming Session Data Storage**. The data model for storing test results and evidence will need to include a foreign key relationship to the `vulnerability_taxonomies` table to link each finding to its classification.
* This provides the structured data needed for **ADR-F3.1: Model Safety, Bias, and Risk Scoring Architecture**.
