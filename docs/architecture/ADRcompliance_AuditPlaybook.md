Here is the expanded and enriched guide for ADR Compliance Audit and Resolution, integrating detailed, actionable content from our previous research.

-----

## ADR Compliance Audit and Resolution: An Operational Playbook

Version: 30JUL25

### Introduction

This document provides a comprehensive, operational framework for auditing a codebase against its Architectural Decision Records (ADRs). In complex, evolving software systems, it is critical to ensure that the implemented architecture aligns with the documented decisions that guide it. Deviations, or "architectural drift," can lead to increased technical debt, security vulnerabilities, and maintenance overhead.

This playbook is designed for practical application by development teams, architects, and engineering leaders. It expands on the foundational concepts by integrating detailed, actionable steps, checklists, and examples, with a specific focus on automation and AI-powered tools within a Python ecosystem. It merges our research on audit preparation, proactive enforcement, and the core audit process into a single, cohesive, end-to-end workflow.

The process is broken down into four distinct phases:

1.  **Phase 1: Preparation and Scoping:** Laying the groundwork for a successful audit.
2.  **Phase 2: Audit Execution:** Conducting the audit through a hybrid of manual and automated techniques.
3.  **Phase 3: Gap Tracking and Resolution:** Systematically managing and remediating identified compliance gaps.
4.  **Phase 4: Proactive Enforcement & Continuous Improvement:** Embedding compliance into the SDLC to prevent future drift.

-----

### Phase 1: Preparation and Scoping

**Objective:** To establish a clear mandate, scope, and plan for the audit, ensuring all prerequisites are met before execution begins. A thorough preparation phase is the single most important predictor of a successful audit.

#### 1.1 Define Clear Audit Objectives

First, define *why* you are conducting the audit. The objectives must be SMART (Specific, Measurable, Achievable, Relevant, Time-bound) and directly linked to business or technical drivers.

**Actionable Steps:**

1.  **Identify Drivers:** Meet with stakeholders (e.g., CTO, Head of Engineering, Product Managers) to identify the primary drivers. Common drivers include:
      * **Modernization:** "We are migrating to a microservices architecture; are we adhering to the new patterns?"
      * **Technical Debt Reduction:** "Our velocity has slowed; which architectural violations are causing the most friction?"
      * **Security & Compliance:** "Can we prove our system complies with SOC 2 requirements documented in our ADRs?"
      * **Scalability & Performance:** "Are we following the caching and database connection patterns required to meet our Q4 performance targets?"
2.  **Translate Drivers to Objectives:** Frame the drivers as measurable audit objectives.
      * *Example:* (Driver: Security) -\> "Verify within 3 weeks that all services handling PII data are using the `secure-db-library` as mandated by ADR-007, with zero exceptions."

#### 1.2 Catalog and Analyze Architectural Decision Records (ADRs)

You cannot audit what isn't defined. This step involves creating a comprehensive, up-to-date, and analyzable inventory of all relevant ADRs.

**Actionable Steps:**

1.  **Locate and Centralize:** Gather all ADRs from wherever they reside (e.g., Git repositories, Confluence, wikis) into a single, accessible location.
2.  **Review and Triage:** For each ADR, assess its current status:
      * **Active:** The decision is current and should be enforced.
      * **Superseded:** A newer ADR has replaced this one. Mark it as such, linking to the new ADR.
        .
      * **Obsolete:** The decision is no longer relevant. Mark it as obsolete.
3.  **Address Gaps:**
      * **Undocumented Decisions:** For critical, un-documented architectural rules, conduct "retroactive ADR workshops" with senior engineers to formally write them down.
      * **Ambiguous Decisions:** For ADRs with unclear consequences (e.g., "We should use asynchronous communication"), clarify them. A better version: "For inter-service communication between domains, commands must be sent via RabbitMQ using the schema defined in ADR-011."
4.  **Create a Traceability Matrix:** Develop a spreadsheet or use a dedicated tool to map each **Active ADR** to the system's components. This matrix is the foundation of the audit scope.

| ADR ID | Decision Summary | Status | Impacted Modules/Services | Verifiable Rule (Link to Test/Policy) |
| :--- | :--- | :--- | :--- | :--- |
| ADR-007 | Use `secure-db-library` for PII | Active | `user-service`, `auth-service` | `test_db_library_enforcement.py` |
| ADR-011 | Use RabbitMQ for cross-domain | Active | `order-service`, `inventory-svc` | `check_cross_domain_imports.py` |

#### 1.3 Conduct an Architectural Risk Assessment

Prioritize the audit effort by identifying which architectural violations pose the greatest risk.

**Actionable Steps:**

1.  **Identify Risk Categories:** Define risk categories relevant to your context (e.g., Security, Performance, Reliability, Maintainability, Compliance).

2.  **Score and Prioritize:** For each ADR in your traceability matrix, assess the risk of its violation using a simple risk matrix. Score Likelihood and Impact on a 1-5 scale.

      * **Likelihood:** How likely is it that this rule is currently being violated? (Consider code complexity, team experience, etc.)
      * **Impact:** What is the business impact if a violation occurs? (e.g., Data breach, system outage, significant rework).
      * **Risk Score = Likelihood x Impact**

3.  **Focus the Audit:** High-risk score ADRs should be the top priority for both manual review and automated analysis.

#### 1.4 Assemble the Audit Team

Select a cross-functional team with the right skills and context.

  * **Audit Lead/Architect:** Owns the audit process, facilitates meetings, and synthesizes the final report.
  * **Senior Developers (2-3):** Provide deep context on the codebase and implementation history. They are the primary manual reviewers.
  * **Security Analyst (Optional but recommended):** Focuses on security-related ADRs and vulnerabilities.
  * **DevOps/SRE:** Provides context on infrastructure, deployment, and operational ADRs.

#### 1.5 Create a Formal Audit Plan

A concise document that serves as the charter for the audit.

**Plan Sections:**

1.  **Audit Objectives:** (From step 1.1)
2.  **Scope:**
      * **In-Scope:** List the specific repositories, services, and ADRs to be audited (derived from the traceability matrix and risk assessment).
      * **Out-of-Scope:** Explicitly state what will *not* be audited.
3.  **Timeline & Milestones:** Define start/end dates and key milestones (e.g., "Week 1: ADR Analysis Complete," "Week 3: Automated Scans Complete," "Week 4: Final Report Published").
4.  **Deliverables:** List the expected outputs (e.g., "Audit Findings Report," "Jira tickets for all gaps," "New automated tests").
5.  **Success Criteria:** How will you know the audit was successful? (e.g., "100% of high-risk ADRs have been audited," "A prioritized backlog of all identified architectural debt is created.")

#### Phase 1 Checklist

Use this checklist to ensure readiness before starting the audit execution.

  - [ ] Audit objectives defined and approved by stakeholders.
  - [ ] All ADRs are centralized, reviewed, and triaged (Active, Superseded, Obsolete).
  - [ ] Traceability matrix mapping ADRs to code is complete.
  - [ ] Risk assessment is complete; high-risk ADRs are identified.
  - [ ] Audit team is assembled and roles are clear.
  - [ ] Formal audit plan is written and socialized.
  - [ ] All required documentation (C4 diagrams, code repos, performance logs) is accessible.

-----

### Phase 2: Audit Execution

**Objective:** To systematically execute the audit plan, identify compliance gaps using a combination of manual and automated methods, and document all findings.

#### 2.1 Manual Peer Review (Architecture-Focused)

Manual reviews are essential for assessing the "why" behind the code, evaluating qualitative aspects, and auditing ADRs that are difficult to automate.

**Actionable Steps:**

1.  **Schedule Architectural Review Meetings:** For each high-risk area identified in Phase 1, schedule dedicated review sessions.
2.  **Set a Clear Agenda:**
      * **ADR Under Review:** State the specific ADR being audited (e.g., ADR-015: Layering Rules for the `billing-service`).
      * **Code Presentation:** The lead developer of the component walks through the relevant code, explaining how it complies with the ADR.
      * **Guided Questioning:** The Audit Lead facilitates, asking probing questions: "How does this handle database connections? ADR-009 states...". "Show me the error handling path. How does that align with ADR-021?".
      * **Document Findings:** A designated scribe records all identified deviations in a structured format.

#### 2.2 Automated Static and Dynamic Analysis

Automated analysis provides broad, repeatable, and efficient enforcement of quantifiable architectural rules. This is where the fitness functions and policies are executed.

**Actionable Steps:**

1.  **Execute Fitness Functions:** Run the suite of architectural tests developed to enforce your ADRs (see Phase 4 for development details).
      * `pytest --arch -m "high_risk"` - Execute the test suite, potentially filtering for tests covering high-risk ADRs.
2.  **Run Policy Checks:** Execute Policy as Code (PaC) scans for infrastructure and cross-cutting concerns.
      * `opa eval -d policy/ -i input.json 'data.myapp.authz.allow'` - Run an OPA policy check.
3.  **Analyze Tool Output:** Triage the results from the automated tools.
      * **Failures:** Each failure represents a clear architectural violation.
      * **Exceptions:** Review any tests that were intentionally skipped. Is the reason for skipping still valid?

#### 2.3 Synthesize and Document Findings

Combine the results from both manual and automated methods into a single, consolidated list of findings.

**Actionable Steps:**

1.  **Correlate Findings:** Match manual findings with automated results. A manual finding confirmed by an automated test failure is a high-confidence gap.
2.  **Create a Finding Record:** For each unique gap, create a detailed record *before* it goes into a backlog. This record should contain:
      * **Finding ID:** A unique identifier.
      * **Description:** What is the gap?
      * **ADR Violated:** Link to the specific ADR.
      * **Evidence:** Code snippets, log excerpts, terminal output.
      * **Risk Score:** The score calculated in Phase 1.
      * **Recommended Action:** A preliminary suggestion for remediation.

-----

### Phase 3: Gap Tracking and Resolution

**Objective:** To translate audit findings into actionable work items, prioritize them based on risk, and manage them to resolution.

#### 3.1 Gap Tracking in an Issue Management System

Use your existing issue tracker (e.g., Jira, GitHub Issues) to manage architectural debt like any other work item.

**Actionable Steps:**

1.  **Create a "Gap Finding" Ticket Template:** In Jira, create a new issue type or use a dedicated Epic for architectural debt. The template should include the fields from the "Finding Record" (3.3).
2.  **Log All Findings:** Create a new ticket for every finding from the audit.
3.  **Assign Ownership:** Assign each ticket to a "Remediation Owner" (typically a tech lead or senior engineer of the affected component).

#### 3.2 Formulating a Remediation Plan

Develop a strategic plan to address the identified gaps. Not everything can or should be fixed immediately.

**Actionable Steps:**

1.  **Prioritization Meeting:** The Audit Lead and tech leads meet to review the backlog of gap tickets.
2.  **Prioritize Based on Risk:** Use the Risk Score to sort the backlog. High-risk items must be prioritized.
3.  **Define Remediation Strategy:** For each gap, decide on the strategy:
      * **Incremental Refactoring:** The violation can be fixed gradually over several sprints without a major rewrite. This is the preferred approach.
      * **Large-Scale Remediation:** The violation is fundamental and requires a dedicated epic or project (e.g., replacing a non-compliant library across 10 services).
      * **Accept Risk:** In rare cases, the business may decide the cost of fixing outweighs the risk. This decision **must be documented in a new ADR** that supersedes the old one.
4.  **Schedule the Work:** Integrate the prioritized tickets into the team's regular backlog and sprint planning process.

-----

### Phase 4: Proactive Enforcement & Continuous Improvement

**Objective:** To shift from periodic audits to continuous compliance, embedding architectural enforcement directly into the developer workflow. This phase focuses on turning ADRs into code.

#### 4.1 Codifying ADRs: Architecture-as-Code in Python

Translate the natural language of ADRs into machine-verifiable rules.

**Actionable Steps & Tools:**

1.  **For Dependency and Layering Rules:** Use architectural fitness functions.

      * **Tool:** `PyTestArch`
      * **Example (ADR: "The `domain` layer must not import the `api` layer"):**

    <!-- end list -->

    ```python
    # tests/test_architecture.py
    from pytestarch import get_evaluable_architecture, Rule

    def test_domain_does_not_depend_on_api():
        # Arrange
        arch = get_evaluable_architecture(".", ["tests*"])

        # Act
        rule = (
            Rule()
            .modules_that()
            .are_in_package("my_app.domain")
            .should_not()
            .depend_on_modules_that()
            .are_in_package("my_app.api")
        )

        # Assert
        rule.assert_applies(arch)
    ```

2.  **For Granular, Custom Rules:** Write custom linters.

      * **Tool:** `pylint` with custom checkers.
      * **Example (ADR: "The deprecated `old_legacy_util` must not be used"):** A custom `pylint` checker can be written to traverse the code's Abstract Syntax Tree (AST) and fail if it finds an `Import` or `ImportFrom` node referencing `old_legacy_util`.

3.  **For Cross-Cutting & Infrastructure Rules:** Use Policy as Code.

      * **Tool:** Open Policy Agent (OPA) with its language Rego.
      * **Example (ADR: "All new S3 buckets must have encryption enabled"):** A Rego policy can be written to inspect Terraform or CloudFormation plans and deny any that define an `aws_s3_bucket` resource without the `server_side_encryption_configuration` block.

#### 4.2 The Role of AI in Automating Rule Creation

Use AI, particularly Large Language Models (LLMs), to accelerate the translation of ADRs into code. This is an assistive process, not full automation.

**Actionable Steps:**

1.  **Structure the ADR for AI:** Ensure your ADRs have a clear, machine-readable "Decision" section.
2.  **Use Prompt Engineering:** Craft a prompt that provides the LLM with the ADR, context about the desired tool, and asks for the code.
      * **Example Prompt:**
        ```prompt
        You are an expert Python software architect. I will provide you with an Architectural Decision Record (ADR) and a target tool. Your task is to generate a verifiable code rule that enforces the decision in that ADR.

        **ADR-025: Isolate Business Logic from Frameworks**
        * **Decision:** The `services` layer, which contains core business logic, must not contain any code that imports from the `django` framework. This ensures our business logic is portable and not tightly coupled to the web framework.

        **Target Tool:** `PyTestArch`

        Generate the Python code for the `PyTestArch` test case to enforce this rule.
        ```
3.  **Review and Refine:** Always have a human expert review, refine, and test the AI-generated code before committing it.

#### 4.3 CI/CD Integration: The Gating Mechanism

Embed these automated checks directly into your CI/CD pipeline to provide fast feedback and prevent drift.

**Actionable Steps:**

1.  **Pre-Commit Hooks:** Run lightweight linters and dependency checkers locally before code is even committed.
2.  **Pull Request (PR) Checks:** The full suite of `PyTestArch` fitness functions and `pylint` checks must pass before a PR can be merged. This is the primary gate for preventing architectural violations.
3.  **Deployment Pipeline Checks:** OPA policy checks should run against infrastructure-as-code changes before they are applied to any environment.

#### 4.4 AI-Powered Continuous Monitoring

Go beyond pass/fail checks by using AI to monitor architectural health over time and detect negative trends.

**Actionable Steps:**

1.  **Identify Key Metrics:** Track metrics that represent architectural health (e.g., cyclomatic complexity, afferent/efferent coupling, dependency graph stability, number of policy violations).
2.  **Leverage AIOps Tools:** Use platforms like `New Relic AI` or `Datadog` to ingest these metrics.
3.  **Configure Anomaly Detection:** Configure the AIOps tool to learn the baseline for your architectural metrics and alert on significant deviations or negative trends (e.g., "Coupling between the `auth` and `payment` services has increased by 40% over the last month"). This provides an early warning of architectural drift, allowing you to intervene before it becomes a major violation.
