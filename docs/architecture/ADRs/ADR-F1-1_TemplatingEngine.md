# ADR-F1.1: Sandboxed Templating Engine for Attack Payloads

## Status
Accepted

## Authors
Tam Nguyen (Cybonto)

## Date

2025-07-27

## Stakeholders

  * API Development Team
  * Security and Compliance Team
  * Security Researchers and Red Teamers (Primary Users)
  * Platform Operations Team

## Context

Effective AI red teaming requires the ability to generate not just single, static prompts, but thousands of dynamic, adversarial prompt variations. These prompts often need to be constructed programmatically, combining base text with wordlists, applying various encoding functions (e.g., Base64, Leetspeak), and using conditional logic to bypass a model's safety filters.

Therefore, the API must provide a powerful, yet secure, mechanism for users to define and render these attack payloads. The choice of this templating engine is critical: it must be expressive enough to create sophisticated attacks but also secure enough that the engine itself cannot be turned into an attack vector against the ViolentUTF platform. A user-submitted template must never be able to compromise the server environment.

-----

## Considered Options

### 1\. Simple String Substitution

This approach would involve the API accepting a template with basic placeholders (e.g., `Hello, {name}`) and a set of key-value pairs for substitution.

  * **Pros**:
      * Extremely simple to implement and completely safe from code injection vulnerabilities.
  * **Cons**:
      * **Insufficiently Powerful**: Lacks the expressive power needed for modern red teaming. It cannot handle loops (e.g., iterating over a list of malicious payloads), conditional logic, or transformation functions, making it unfit for purpose.

### 2\. General-Purpose Templating Engine (e.g., Jinja2)

This approach involves integrating a mature, feature-rich templating engine like Jinja2. This would give users access to loops, conditionals, macros, and filters.

  * **Pros**:
      * **Maximum Expressive Power**: Provides the flexibility needed to construct highly complex and dynamic prompt sets.
      * **Mature and Well-Documented**: Leverages a widely-used library with a low learning curve for many developers.
  * **Cons**:
      * **Extreme Security Risk**: If not properly configured, this approach is highly vulnerable to **Server-Side Template Injection (SSTI)**. A malicious user could craft a template that executes arbitrary code on the platform's servers, leading to a catastrophic compromise.

### 3\. Custom Domain-Specific Language (DSL)

This approach involves designing and implementing a new, custom mini-language specifically for defining attack payloads. The platform would include a parser and a safe execution environment for this DSL.

  * **Pros**:
      * **Most Secure Option**: By controlling the entire language and its execution, we can eliminate the possibility of code injection attacks by design.
  * **Cons**:
      * **Massive Engineering Effort**: Designing, building, documenting, and maintaining a custom language is a huge and costly undertaking.
      * **High Friction for Users**: Requires users to learn a new, proprietary language, which acts as a barrier to adoption.

-----

## Decision

The ViolentUTF API will adopt a mature, general-purpose templating engine, specifically **Jinja2**, to provide maximum power and flexibility to users.

To mitigate the critical security risks, this engine will be executed exclusively within a **strictly controlled, sandboxed environment**.

1.  **Engine**: Jinja2 will be the chosen templating engine.
2.  **Sandboxing**: All user-submitted templates will be rendered using Jinja2's `SandboxedEnvironment`. This environment will be configured to disable access to dangerous Python built-ins, methods, and attributes.
3.  **Custom Functions**: A curated library of safe, custom **filters and functions** will be exposed to the template environment. These will correspond to the platform's prompt "converters" (e.g., Base64 encoding), providing a controlled way to perform transformations.
4.  **Resource Limiting**: Template rendering will be executed with strict resource limits (CPU time and memory) to prevent Denial-of-Service attacks from computationally expensive or malicious templates.

-----

## Rationale

This decision provides the best balance of user empowerment, implementation pragmatism, and security.

1.  **Empowers Users without Reinventing the Wheel**: This approach gives security researchers the powerful, expressive tools they need (loops, conditionals, functions) to create sophisticated attacks. It achieves this by leveraging a mature, well-known library instead of incurring the massive cost and time-to-market delay of building a custom DSL.

2.  **Security Through Controlled Sandboxing**: The decision directly confronts the primary risk of SSTI by making the sandbox a non-negotiable part of the design. By using Jinja2's built-in sandboxing capabilities and carefully curating the functions available within the template, we can prevent malicious users from escaping the template environment and executing arbitrary code. This is a recognized and robust pattern for safely using powerful tools.

3.  **Seamless Integration with Platform Features**: Making the API's existing prompt converters available as Jinja2 filters (e.g., `{{ my_payload | base64encode }}`) creates a natural, intuitive, and powerful user experience. It deeply integrates the templating engine with other core concepts of the platform.

4.  **Protection Against Resource Exhaustion**: By adding resource limits to the rendering process, we protect the platform's stability and reliability from "runaway" templates (e.g., infinite loops or computationally expensive operations), which is a crucial consideration for a multi-tenant service.

-----

## Implementation Details

  * **Jinja2 Sandboxing**: The implementation will use `jinja2.SandboxedEnvironment`. This environment, by default, prevents access to attributes or methods starting with an underscore (`_`), which blocks access to most of Python's dangerous internal methods.

  * **Exposed Custom Filters**: A library of safe transformation functions will be provided as custom filters. The initial set will include:

      * `| base64encode`
      * `| base64decode`
      * `| urlencode`
      * `| leetspeak`
      * `| reverse`
      * `| json_escape`

  * **Example Template**: A user could provide a template like the one below to generate multiple attack variations from a single base payload.

    ```jinja
    {% set base_payload = "Your account is locked. Click here to fix." %}
    {% set techniques = ["plain_text", "leetspeak", "base64encode"] %}

    {% for tech in techniques %}
    ---
    Attack using technique: {{ tech }}
    Payload:
    {% if tech == "leetspeak" %}
    {{ base_payload | leetspeak }}
    {% elif tech == "base64encode" %}
    {{ base_payload | base64encode }}
    {% else %}
    {{ base_payload }}
    {% endif %}
    {% endfor %}
    ```

-----

## Consequences

  * **Positive**:

      * Provides users with an extremely powerful and flexible tool for generating a vast array of adversarial prompts.
      * The learning curve is low for developers already familiar with common templating engines like Jinja2, Twig, or Liquid.
      * The platform's capabilities can be easily extended by simply adding new, safe custom filters to the sandbox environment.

  * **Negative**:

      * The security of the sandbox implementation itself becomes a critical component of the platform's attack surface. It must be rigorously tested and carefully maintained to prevent bypasses.
      * There is a residual risk, however small, that a flaw in the Jinja2 sandboxing implementation itself could be discovered and exploited.

  * **Technical Impact**:

      * A secure service layer for rendering sandboxed templates must be built.
      * The execution of this service must be wrapped in resource-limiting controls (e.g., running in a separate process with CPU and memory constraints).
      * A library of custom filters must be developed and maintained, with each new filter undergoing a security review.

-----

## Related Artifacts/Decisions

  * This decision provides the "payload generation" capability that is a prerequisite for **ADR-F1.2: Orchestration of Multi-Stage and Multi-Turn Attacks**, as the orchestrator will execute the prompts generated by this templating engine.
  * The security of this component is governed by the principles laid out in the foundational security ADRs.
