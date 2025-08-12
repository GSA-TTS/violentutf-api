# **Agent-Consumable GitHub Issues**

Aug 12, 2025
Author: Tam Nguyen ([https://github.com/Cybonto](https://github.com/Cybonto))

## **1\. Premise & Problem Statement:**

We are at the cusp of a paradigm shift where autonomous and semi-autonomous AI agents will become the primary implementers of software development tasks. The current format of GitHub issues—designed for human-to-human communication—is a fundamental bottleneck. These issues are often conversational, ambiguous, lack explicit constraints, and rely heavily on implicit domain knowledge, leading to high failure rates, significant rework, and a lack of trust in agentic workflows.
To unlock the potential of autonomous software engineering, we must redefine the "issue" itself. We need to move from a prose-based description to a machine-readable, formally specified, and contextually-grounded "work packet" that an agent, such as one powered by **Claude Code**, can parse, plan, and execute with high fidelity.

## **2\. Mandate:**

This document presents a comprehensive research initiative to define a new schema and a set of interaction protocols for creating and managing GitHub issues in the age of AI agents. The primary goal is to develop a framework that maximizes agentic comprehension and minimizes ambiguity and assumption-making. This framework consists of a formal task schema, a model for contextual grounding, a robust human-agent interaction protocol, and a vision for a guided issue creation experience.

## **3\. Research Questions:**

#### **A. Declarative Issue Specification (The "Schema")**

The optimal structure for an agent-consumable issue is a formal schema embedded directly within the issue body, treating the issue as a version-controlled, "as-code" artifact. The recommended format is a **YAML frontmatter** block within the Markdown body, which is both human-readable and machine-parsable. This approach, which we term the **Unified Agentic Task (UAT)**, acts as a forcing function for clarity.
**Proposed Schema: The Unified Agentic Task (UAT)**
The UAT schema is modular, separating metadata, functional specifications, quality constraints, and relational context.

* **Core Metadata:**
  * schemaVersion: (e.g., "uat-v1.0") Versions the schema for backward compatibility.
  * issueID: (e.g., "PROJ-451") An optional, human-readable ID for linking to external trackers.
  * type: An enum classifying the work item, which dictates the agent's high-level strategy.
  * status: The canonical state of the issue in the agentic lifecycle, serving as the single source of truth for the task's progress.
* **Expanded Core Metadata Definitions:**
  * **type (Enum):** This field establishes a formal classification for a work item, drawing from established Agile methodologies. This taxonomy is not just for organizational purposes; it fundamentally dictates the expected structure of the UAT schema and informs the AI agent about the nature of the task it is about to undertake.
    * **epic**: A large-scale initiative or a major feature that is too big to be completed in a single development cycle. An Epic is a container that is broken down into smaller stories and tasks.
      * **Agent's Role**: When an agent processes an epic, its primary role is **planning and decomposition**, not direct coding. It would analyze the high-level goal and might be tasked with generating the initial set of child story and task UATs.
    * **story**: Describes a new feature or functionality from the perspective of an end-user. It is focused on delivering tangible value to the user. The userStory field in the spec block is mandatory for this type.
      * **Agent's Role**: The agent acts as a **feature developer**. Its goal is to write the necessary code to satisfy the acceptanceCriteria and deliver the user-facing functionality.
    * **task**: A specific, discrete piece of work that needs to be done. It is often technical in nature and supports a story or epic, but it doesn't typically deliver direct value to an end-user on its own (e.g., "Set up a database index" or "Configure a CI/CD pipeline").
      * **Agent's Role**: The agent acts as a **technical specialist**. It focuses on executing a well-defined technical action, such as running a script, configuring a service, or setting up infrastructure.
    * **bug**: Represents a defect, error, or flaw in the existing codebase that causes it to behave in an unintended or incorrect way. A bug report must be highly specific, including steps to reproduce the issue.
      * **Agent's Role**: The agent acts as a **debugger and maintenance programmer**. Its primary goal is to identify the root cause of the error, write a fix, and create a regression test to ensure the bug does not reappear.
    * **chore/refactor**: Describes work that is necessary to improve the health, maintainability, or performance of the codebase but does not add new functionality. This includes reducing technical debt, upgrading libraries, or reorganizing code.
      * **Agent's Role**: The agent acts as a **code quality engineer**. It focuses on improving non-functional attributes of the code, guided by the quality block in the UAT, such as improving code coverage or reducing cyclomatic complexity.
  * **status (Enum):** This field represents the **canonical state** of the issue within the agent-aware lifecycle. While GitHub labels are used as a synchronized, filterable *representation* of the state for the UI, the status field within the UAT frontmatter is the **single source of truth**. The agent is responsible for keeping the label and the canonical status field in sync at all times.
* **Non-Functional Requirements (NFRs):** The quality block captures NFRs in a quantifiable way, transforming vague statements into testable constraints. Security constraints from models like STRIDE can be embedded as explicit, testable requirements.
  quality:
    performance:
      response\_time\_p95\_ms: \< 200
    security:
      vulnerability\_scan\_required: true
      data\_encryption\_standard: "AES-256"
    maintainability:
      code\_coverage\_min\_percent: 85

* **Scope and Acceptance Criteria:** The spec block enforces the declaration of scope boundaries and acceptance criteria using a **Behavior-Driven Development (BDD) Gherkin-like format**. This provides an unambiguous, testable definition of "done" that can be directly converted into automated tests by the agent.
  spec:
    userStory: "As a user, I want to log in with my email so that I can access my account."
    acceptanceCriteria:
      \- given: "A user is on the login page"
        when: "They enter valid credentials and click 'Login'"
        then: "They are redirected to their dashboard"
      \- given: "A user is on the login page"
        when: "They enter invalid credentials"
        then: "An error message 'Invalid credentials' is displayed"

#### **B. Contextual Grounding & Linkage**

An agent's effectiveness is directly tied to its contextual understanding. The UAT schema and an event-driven retrieval architecture provide a robust method for linking an issue to its required context.

* **Explicit Linkage via the relations Block:** The schema includes a relations block to explicitly link the issue to its context graph, including pointers to other issues, pull requests, and Architectural Decision Records (ADRs).
  relations:
    parent: "https://github.com/org/repo/issues/100" \# The Epic this story belongs to
    dependsOn:
      \- "https://github.com/org/repo/issues/120" \# Must be completed first
    relatesTo:
      \- "https://github.com/org/repo/wiki/ADR-005-Authentication-Strategy"

* **Proactive Context Injection via Event-Driven Hooks:** To reduce the agent's need for external exploration, we propose an event-driven architecture using **Claude Code hooks**. This moves beyond simple URL linking to proactively embedding context.
  * **UserPromptSubmit Hook:** Triggers on initial task submission. It performs a semantic search of the knowledge base (code, docs, ADRs) based on the UAT's content and injects a broad contextual summary into the agent's initial prompt.
  * **PreToolUse Hook:** This provides just-in-time, highly specific context. When the agent decides to perform an action (e.g., edit auth.go), this hook triggers, retrieves the most relevant documentation for that specific file or command, and injects it directly into the agent's working context. This "query-by-action" is more precise than a natural language search, as the agent's intended action *is* the query.
  *

#### **C. Human-Agent Interaction Protocol (The "Lifecycle")**

The traditional Open/Closed issue lifecycle is insufficient for agentic workflows. We propose an expanded state model and a formal communication protocol to manage the interaction.

* **Expanded State Model:** New states provide transparency into the agent's process. The canonical state is stored in the status field of the UAT, while GitHub labels serve as a synchronized, filterable representation.
  * **Pending-Acceptance**: A validated UAT is ready for an agent to claim.
  * **Agent-Planning**: The agent is analyzing the UAT and generating an execution plan.
  * **Agent-Executing**: The agent is actively modifying code and running commands.
  * **Clarification-Required**: The agent is paused, awaiting unambiguous input from a human.
  * **Awaiting-Human-Review**: The agent has completed its work and submitted a pull request.
  * **Verification-Failed**: The PR was rejected or a CI check failed; the agent is in a rework cycle.
  * **Done**: The PR has been merged.
* **Clarification Protocol:** When an agent requires clarification, it should not use external tools like Slack. To maintain a traceable audit log, all communication occurs in **structured comments on the GitHub issue**. The agent posts a YAML-formatted request detailing its current understanding, the conflict it has encountered, and a set of actionable options for the human to choose from. The human responds by referencing the request and chosen option, allowing the agent to parse the response and resume its work.
* **Future Protocol Enhancements:** The core HAIP can be extended with additional specialized protocols to handle more complex scenarios:
  * **Cost/Benefit Analysis Protocol:** Before entering the Agent-Planning state, the agent could perform a preliminary analysis of the UAT and provide an estimate of complexity, time, or computational cost. The human would then need to approve the estimate before the agent proceeds, preventing unexpected resource consumption on poorly defined tasks.
  * **Security Escalation Protocol:** If the agent, during its execution, discovers a potential security vulnerability not mentioned in the UAT (e.g., an exposed secret or a dependency with a known CVE), it should not attempt to fix it directly. It would enter a new Security-Hold state and use this protocol to notify a designated security team, providing all relevant details for human-led triage.
  * **Knowledge Gap Protocol:** If the agent's context retrieval hooks fail to find relevant documentation for a specific file or concept, it can trigger this protocol. The agent would create a new, placeholder documentation file (e.g., docs/modules/new\_module.md) with a summary of what it *thinks* the module does and a to-do list for a human to complete, thus proactively helping to improve the project's knowledge base.


#### **D. The Issue Creation Experience**

To guide users in providing the necessary structured data, the issue creation process must be redesigned from a static form into a dynamic, interactive experience.

* **Leveraging GitHub Issue Templates:** The foundation for a better experience is to use GitHub's native issue template feature. Create a separate Markdown file in the .github/ISSUE\_TEMPLATE/ directory for each UAT type (e.g., bug.md, story.md). Each template will contain the boilerplate YAML frontmatter for that type, guiding the user to fill in the required fields.
  *Example .github/ISSUE\_TEMPLATE/bug.md:*
  \---
  name: 🐞 Bug Report
  about: Create a report to help us improve
  title: 'Bug: '
  labels: 'type:bug'
  \---
  \---
  schemaVersion: "uat-v1.0"
  issueID: ""
  type: "bug"
  status: "Pending-Acceptance"
  priority: 3
  assignee: ""
  spec:
    userStory: ""
    acceptanceCriteria:
      \- given: ""
        when: ""
        then: ""
  quality: {}
  relations: {}
  \---

  \*\*Describe the bug\*\*
  A clear and concise description of what the bug is.

  \*\*To Reproduce\*\*
  Steps to reproduce the behavior:
  1\. Go to '...'
  2\. Click on '....'
  3\. Scroll down to '....'
  4\. See error

* **Interactive "Issue Bot" for Guided Creation:** The ideal solution is an interactive **"Issue Bot"** that interviews the creator. This bot, likely implemented as a GitHub App that listens for issues.opened webhooks, would engage the user in a dialogue to populate the UAT schema.
  * **Architecture**: A serverless function (e.g., AWS Lambda, Google Cloud Function) is triggered when a new issue is created. It parses the initial issue body. If the UAT block is incomplete, it initiates the conversational flow.
  * **Interactive Guidance**: Instead of the user editing YAML directly, the bot posts comments with targeted questions based on the selected issue type and the content already provided.
    * *User selects type: bug*: The bot asks, "What are the steps to reproduce this bug?" and "What was the expected behavior?"
    * *User writes "the page should be fast"*: The bot responds, "I see you've mentioned performance. To make this actionable, can you please specify the performance budget? For example, what is the target P99 latency in milliseconds for this endpoint?"
    * *User creates a story*: The bot asks, "Which user roles are affected by this story?" and "Can you define the acceptance criteria in a 'Given-When-Then' format? I can help you structure it."
  * **Schema Population and Validation**: The bot uses the user's answers to dynamically edit the issue body, constructing the UAT YAML block. Once all required fields are populated, it validates the schema. If valid, it adds a final comment, "UAT specification complete. The issue is now ready for an agent," and applies the Pending-Acceptance label.

**4\. Desired Deliverables:**
This research framework directly yields the following actionable deliverables:

* **A. Formal Schema Definition:** An example of a complete UAT for a bug fix.
  \---
  schemaVersion: "uat-v1.0"
  issueID: "PROF-17"
  type: "bug"
  status: "Pending-Acceptance"
  priority: 1
  assignee: "claude-code-agent"
  spec:
    userStory: "As a user on Safari, I want my new avatar to be displayed immediately after a successful upload so that I know the change was successful."
    acceptanceCriteria:
      \- given: "A logged-in user on the Safari browser is on their profile page"
        when: "They upload a new valid image file as their avatar"
        then: "The new avatar image is displayed on the page within 1 second of the upload completing"
  quality:
    performance:
      response\_time\_p95\_ms: \< 250
    compatibility:
      supported\_browsers: \["Safari \>= 17.0"\]
  relations:
    parent: "https://github.com/org/repo/issues/100"
  \---
  \*\*Steps to Reproduce:\*\*
  1\. Log in using Safari.
  2\. Navigate to the profile page.
  3\. Upload a new avatar.

  \*\*Actual Behavior:\*\*
  The old avatar remains visible until a hard refresh. This suggests a caching issue.

* **B. Guideline Document Principles:**
  * **Structure for Parsability:** Use hierarchical Markdown headers and a logical docs/ folder structure, as this is used by the agent's indexing pipeline to automatically create semantic chunks and metadata tags.
  * **Write for Clarity and Atomicity:** Each paragraph should focus on a single idea to improve the quality of vector embeddings for semantic search.
  * **Leverage Frontmatter:** Use YAML frontmatter in documentation files to provide explicit metadata (e.g., tags, owner) that guides the agent's retrieval engine.
  * **Prioritize Code Examples:** Provide complete, copy-pasteable code examples and precise API signatures, as these are high-value assets for an implementation agent.
* **C. Proposed State-Transition Diagram:** A formal diagram illustrating the agent-aware issue lifecycle.
  stateDiagram-v2
      direction LR
      \[\*\] \--\> Pending\_Acceptance
      Pending\_Acceptance \--\> Agent\_Planning: Agent accepts task
      Agent\_Planning \--\> Agent\_Executing: Plan generated
      Agent\_Planning \--\> Clarification\_Required: Cannot create plan
      Agent\_Executing \--\> Awaiting\_Human\_Review: Submits Pull Request
      Agent\_Executing \--\> Clarification\_Required: Encounters ambiguity
      Agent\_Executing \--\> Verification\_Failed: Automated check fails
      Clarification\_Required \--\> Agent\_Executing: Human provides input
      Awaiting\_Human\_Review \--\> Done: PR Approved & Merged
      Awaiting\_Human\_Review \--\> Verification\_Failed: PR Rejected
      Verification\_Failed \--\> Agent\_Planning: Begins rework cycle
      Done \--\> \[\*\]

* **D. Conceptual Design for an Interactive Issue Creation Process:** An "Issue Bot" that uses a conversational interface to guide a human user through the process of populating the UAT schema, asking targeted questions to ensure all required fields are filled with precise, measurable, and actionable data.
* **E. Identification of Open Problems and Future Research:**
  * **Autonomous Documentation Updates:** Extending the agent's capabilities to allow it to *write back* to the documentation after a code change, combating documentation drift.
  * **Learning from Feedback:** Implementing a mechanism for the agent to learn from pull request review comments to improve its coding patterns over time.
  * **Multi-Modal Context:** Expanding the indexing pipeline to ingest and reason about non-textual artifacts like Figma design files, architecture diagrams, and video tutorials.
  * **Autonomous Task Decomposition:** Enabling a "Planner" agent to autonomously break down vague business goals into a hierarchy of structured UAT epics, stories, and tasks.

This research serves as the cornerstone for building the next generation of reliable and scalable autonomous software development systems, with a practical focus on immediate implementation using tools like **Claude Code**.
