# ADR-F3.2: Server-Side Engine for Automated Report Generation

## Status
Accepted

## Authors
Tam Nguyen (Cybonto)

## Date
2025-07-27

## Stakeholders
* API Development Team
* Security Researchers and Red Teamers (Primary Users)
* Business Stakeholders and End Users (Report Consumers)
* Platform Operations Team

## Context
The culmination of a security testing engagement is often a formal, shareable report that summarizes the methodology, findings, and recommendations. To deliver high value, the ViolentUTF platform must be able to automate the creation of these professional reports in standard, portable formats like PDF and structured JSON.

The platform's API already specifies a comprehensive "Report Setup" feature, which allows users to choose templates, configure content "blocks" (e.g., `executive_summary`, `ai_analysis`), and select the data from specific test runs. This ADR defines the backend architecture required to take a user's saved `Report Configuration` and render it into a final, high-quality document. Report generation is a resource-intensive, long-running process and must be designed as such.

---
## Considered Options

### 1. Client-Side Rendering
In this model, a dedicated web UI would fetch the necessary report data from various API endpoints and render the report dynamically in the user's browser. The user would then rely on the browser's built-in "Print to PDF" functionality to create a static copy.

* **Pros**:
    * Allows for highly interactive reports with filtering, sorting, and drill-down capabilities.
    * Offloads the rendering workload from the server to the client's machine.
* **Cons**:
    * **Cannot Reliably Generate Server-Side Artifacts**: This approach does not fulfill the core requirement of an automated, server-side process that can generate a PDF and save it for later download or distribution (e.g., via email).
    * **Inconsistent Output**: The quality and layout of a PDF generated via a browser's print function can vary dramatically between different browsers, operating systems, and user settings.
    * **Limited for Automation**: Does not provide a path for a purely programmatic, API-driven report generation workflow.

### 2. Server-Side Rendering Engine
This approach involves a dedicated backend service that programmatically generates the report files. The typical process is to gather all necessary data, populate an HTML template, and then use a headless browser library to render the final, pixel-perfect HTML as a PDF.

* **Pros**:
    * **Produces Consistent, High-Quality Artifacts**: The server has full control over the rendering environment, ensuring every generated PDF is identical and professional.
    * **Fully Automatable**: The entire process can be triggered by a single API call, supporting fully automated workflows.
    * **Meets All Requirements**: Directly supports the generation of multiple output formats (`pdf`, `json`) on the backend as required by the Report Setup API.
* **Cons**:
    * **Resource Intensive**: PDF generation using headless browsers is notoriously high in CPU and memory consumption.
    * **More Backend Complexity**: Requires a dedicated worker fleet and a more complex backend architecture to manage these intensive jobs.

---
## Decision
The ViolentUTF platform will implement a **dedicated, server-side report generation engine**.

1.  **Asynchronous Execution**: Report generation will be managed as a **long-running, asynchronous task**, fully integrating with the architecture defined in ADR-007.
2.  **HTML to PDF Rendering**: The core process will involve programmatically populating **HTML/CSS templates** with the relevant report data. A **headless browser library** (e.g., Playwright) will then be used to convert the final HTML document into a PDF.
3.  **Composable Block Architecture**: The engine will be designed as a **composition engine**. It will dynamically build a report by assembling the various content "Blocks" (e.g., `executive_summary`, `detailed_findings`) specified in the user's `Report Configuration`.
4.  **Multi-Format Output**: The engine will first aggregate all data into a structured JSON object. This object will be used to populate the HTML template for PDF rendering and will also be saved directly as the `json` output format.

---
## Rationale

A server-side engine is the only approach that meets the platform's requirements for producing automated, consistent, and high-quality report artifacts.

1.  **Fulfills the API Contract**: The Report Setup API explicitly allows users to request a `pdf` file as an output format. A server-side engine is the only reliable way to fulfill this promise and deliver a consistent, high-quality file to the user.

2.  **Ensures Professionalism and Consistency**: By controlling the entire rendering pipeline on the server, we guarantee that every report, regardless of who generated it or from where, has the exact same professional layout, branding, and formatting. This is critical for customer-facing documents.

3.  **Enables Full Automation and Integration**: The entire report generation process can be triggered via a single API call. This allows users to integrate reporting into their automated CI/CD pipelines or other security workflows (e.g., "run scan, then automatically generate and email the PDF report").

4.  **Supports Advanced, Data-Intensive Blocks**: The server-side architecture allows for complex data aggregation and even further analysis during report creation. This is essential for features like the `ai_analysis` block, where the reporting worker may need to make its own calls to an LLM to generate summary insights for the report.

---
## Implementation Details

### Execution Flow
1.  A client makes a `POST` request to an endpoint like `/api/v1/reports/generate`, providing a `config_id`.
2.  The API server validates the request, enqueues a "report generation" job in the task queue (per ADR-007), and immediately responds with `202 Accepted` and a `task_id`.
3.  A dedicated **"reporting worker"** process picks up the job.
4.  **Data Aggregation**: The worker reads the `Report Configuration` and queries all necessary data from the platform's data stores (per ADR-F2.2), including test summaries, detailed evidence, scores, and taxonomy definitions.
5.  **Composition**: The worker assembles a single, large JSON object containing all the data needed for the report, structured according to the enabled "blocks" in the configuration. This JSON object itself is one of the final outputs.
6.  **HTML Rendering**: This JSON object is passed as context to a main Jinja2 template. The template dynamically includes sub-templates for each requested block, rendering a single, complete HTML document.
7.  **PDF Conversion**: The worker uses a headless browser library to load the generated HTML and print it to a PDF file.
8.  **Storage and Completion**: The final PDF and JSON files are saved to Blob Storage. The worker updates the task status to `SUCCESS` and includes URLs for downloading the generated artifacts.

### Recommended Technology Stack
* **Asynchronous Tasks**: Celery (consistent with ADR-007).
* **HTML Templating**: Jinja2 (consistent with ADR-F1.1).
* **PDF Rendering**: **Playwright**, as it is a modern, well-supported library in the Python ecosystem for controlling headless browsers.

---
## Consequences

* **Positive**:
    * The platform gains a powerful, high-value feature that allows users to create professional, shareable reports.
    * The architecture is highly flexible and can support a wide variety of custom report layouts and content through the template/block system.
    * The process is fully automated and can be integrated into larger workflows.

* **Negative**:
    * **High Resource Consumption**: PDF generation via headless browsers is very demanding on CPU and memory. The reporting worker fleet will need to be carefully sized and monitored.
    * **Front-End Development Effort**: Creating and maintaining a library of high-quality, professional-looking HTML/CSS report templates is a significant front-end development task.

* **Technical Impact**:
    * Requires a new class of background worker specifically configured for report generation, including the installation of a headless browser and its dependencies within the container.
    * A robust system for discovering, managing, and rendering report templates and blocks must be created.
    * The application's data access layer must be extended with queries specifically designed to aggregate data for reporting purposes.

---
## Related Artifacts/Decisions
* This ADR provides the backend implementation for the features described in **`API_Report_Setup_Endpoints.md`**.
* This is a primary consumer of the data storage strategies from **ADR-F2.2 (Data Storage)** and the analysis results from **ADR-F3.1 (Scoring Architecture)**.
* The execution relies on the asynchronous architecture from **ADR-007 (Asynchronous Task Processing)**.
