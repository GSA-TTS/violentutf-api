# ADR-F3.1: Hybrid Scoring Architecture for Model Risk Analysis

## Status

Accepted

## Authors

Tam Nguyen (Cybonto)

## Date

2025-07-27

## Stakeholders

  * API Development Team
  * Security Researchers and Red Teamers (Primary Users)
  * Data Scientists
  * Platform Operations Team

## Context

To provide maximum value, the red teaming platform must go beyond simple pass/fail results. It needs to provide users with quantitative, objective metrics about a target model's risk posture. This includes scoring model responses for characteristics like toxicity, bias, helpfulness, and susceptibility to specific attack patterns.

The analytical techniques ("scorers" or "detectors") required for this vary greatly in computational cost. Some are lightweight (e.g., regular expression matching for refusal phrases), while others are extremely expensive (e.g., using another LLM as a judge to score a response, performing semantic analysis).

The architecture must therefore balance the user's need for immediate feedback during a test run with the platform's ability to perform deep, computationally expensive analysis without unacceptably slowing down the core test execution.

-----

## Considered Options

### 1\. Real-time Synchronous Scoring

This approach involves applying all configured scorers to each model response as it is received, during the main test execution loop. The score is computed before the next prompt is sent.

  * **Pros**:
      * Provides immediate, comprehensive feedback to the user.
  * **Cons**:
      * **Severe Performance Bottleneck**: If any scorer is computationally expensive, it will dramatically increase the total test execution time. A test of 100 prompts could be slowed from minutes to hours.
      * **Tightly Coupled**: The analysis logic is tightly coupled to the test execution logic, making the system less modular and resilient.

### 2\. Batch-based Asynchronous Scoring

This approach involves first completing the entire red teaming session and storing all the raw prompt-response pairs. After the session is complete, a separate, asynchronous batch job is triggered to analyze and score all the results.

  * **Pros**:
      * **Highly Efficient Execution**: The core test run is not slowed down by analysis and completes as quickly as possible.
      * **Decoupled and Scalable**: The resource-intensive analysis work can be scaled on a separate fleet of workers, independent of the test execution workers.
  * **Cons**:
      * **Delayed Results**: The user receives no feedback on the quality of responses until the entire batch analysis process is complete, which could be long after the initial test run finishes.

### 3\. Hybrid Real-time and Batch Scoring

This approach combines the two models. A set of lightweight "triage" scorers are run in real-time during the test. After the test completes, a separate batch process is triggered to run the more comprehensive, heavyweight "deep analysis" scorers.

  * **Pros**:
      * **Best of Both Worlds**: Provides immediate feedback on obvious issues via triage scoring, while ensuring the final results are based on a deep, thorough analysis.
      * **Optimal User Experience**: Users get both speed during the test and depth in the final report.
      * **Efficient Resource Use**: Protects the core test execution loop from performance bottlenecks while still allowing for powerful analytical techniques.

-----

## Decision

The ViolentUTF platform will adopt a **Hybrid Scoring Architecture** that combines real-time and batch processing.

1.  **Two-Phase Analysis**: Scoring will be performed in two distinct phases:
      * **Phase 1: Real-time "Triage" Scoring**: During the test execution, a set of lightweight, low-latency scorers (e.g., keyword matching, regex) will be applied synchronously to each response to provide immediate flags and preliminary scores.
      * **Phase 2: Asynchronous "Deep Analysis"**: After the test run is fully complete, a separate asynchronous batch job will be triggered to apply all configured computationally expensive scorers (e.g., calls to classifier models, semantic analysis, bias measurement).
2.  **Extensible Scorer Plugins**: The platform will implement an extensible **"Scorer Plugin" architecture**, similar to the one for provider integration (ADR-F1.3). This will allow new scoring techniques and models to be added easily as self-contained plugins.

-----

## Rationale

This hybrid decision provides the most robust, flexible, and user-friendly solution for a sophisticated security testing platform.

1.  **Optimizes the User Experience**: The hybrid model delivers the best possible experience. Users performing interactive tests get immediate feedback on whether a prompt was successful, while automated, large-scale tests benefit from a final report enriched with deep, nuanced analysis.

2.  **Maximizes Efficiency and Scalability**: Decoupling expensive analysis from the primary test execution loop is critical for performance and scalability. It ensures that test runs are not blocked by analysis, and it allows the resource-intensive scoring workloads to be managed and scaled independently, optimizing infrastructure costs.

3.  **Future-Proofs the Platform's Analytical Capabilities**: The AI security landscape changes constantly. The Scorer Plugin architecture ensures that the platform is not locked into a specific set of analytical techniques. As new methods for measuring risk are developed, they can be easily integrated as new plugins without requiring changes to the core platform architecture.

-----

## Implementation Details

### Execution and Scoring Flow

1.  An orchestration worker (from ADR-F1.2) receives a response from a target AI model.
2.  **Triage Scoring**: The worker immediately runs all configured `real-time` scorer plugins on the response. The resulting "triage scores" are saved alongside the prompt/response evidence document in the document database.
3.  The orchestration continues until it reaches a final state.
4.  **Deep Analysis Trigger**: Upon completion, the orchestration worker enqueues a new "deep analysis" job into the task queue (from ADR-007), passing it the unique `session_id`.
5.  **Batch Processing**: A separate "scoring worker" process picks up this job. It retrieves all evidence documents for the given `session_id`.
6.  **Deep Scoring**: The scoring worker iterates through the evidence, applying the configured `batch` scorer plugins.
7.  **Result Update**: The worker updates the evidence documents with the new, richer "deep analysis" scores and updates the high-level `session_summary` in the relational database to mark the analysis as complete.

### Scorer Plugin Interface

A simplified Python example of the abstract base class for scorer plugins:

```python
from abc import ABC, abstractmethod
from typing import Literal

class ScorerPlugin(ABC):
    """Abstract interface for all scoring and analysis plugins."""

    # Defines when the scorer should be run.
    SCORER_TYPE: Literal["real-time", "batch"]

    # A unique name for the scorer.
    SCORER_NAME: str

    @abstractmethod
    def score(self, prompt_text: str, response_text: str) -> dict:
        """
        Analyzes a prompt/response pair and returns a structured score object.
        Example: {"score": 0.95, "category": "toxicity", "details": "Contains hate speech"}
        """
        pass
```

-----

## Consequences

  * **Positive**:

      * The platform can deliver both immediate, useful feedback and deep, high-quality final reports.
      * The architecture is highly extensible, allowing new analytical capabilities to be added easily.
      * The system is more scalable and cost-effective, as expensive workloads are decoupled and can be managed independently.

  * **Negative**:

      * Increases the overall complexity of the system. A "test run" now has two distinct lifecycle phases: execution and analysis.
      * The user interface and API clients must be designed to clearly communicate the status of the analysis (e.g., "Execution Complete, Analysis in Progress...").
      * There will be a delay between the end of a test run and the availability of the full, detailed results.

  * **Technical Impact**:

      * Requires the development of a Scorer Plugin registration and execution system.
      * The background worker architecture (ADR-007) must be designed to support this two-phase job chain (execution followed by analysis).
      * The data models (ADR-F2.2) must be designed to accommodate scores being added at two different times. For example, the `session_summary` table needs an `analysis_status` column.

-----

## Related Artifacts/Decisions

  * This architecture is a primary consumer of the data stored according to **ADR-F2.2 (Data Storage)**, reading evidence from the document database.
  * It provides the rich, quantitative data that will be used by the reporting features defined in **ADR-F3.2 (Automated Report Generation)**.
  * It extends the extensible plugin concept from **ADR-F1.3 (Integration Architecture)** to scoring and analysis.
