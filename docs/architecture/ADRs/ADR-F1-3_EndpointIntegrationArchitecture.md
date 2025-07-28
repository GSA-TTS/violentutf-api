# ADR-F1.3: Extensible Plugin Architecture for Target AI Integration

## Status
Accepted

## Authors
Tam Nguyen (Cybonto)

## Date

2025-07-27

## Stakeholders

  * API Development Team
  * Security Researchers and Red Teamers (Primary Users)
  * Platform Operations Team
  * Partner Integration Team (Future)

## Context

The AI landscape is fragmented and rapidly evolving. Users of the ViolentUTF platform will need to test a wide and growing variety of AI systems, including commercial APIs from providers like OpenAI, Anthropic, and Google, as well as open-source models served via platforms like Ollama or Hugging Face. Each of these targets has a unique API, a different data format for requests and responses, and distinct authentication requirements.

A scalable and maintainable architecture is required to abstract these differences. The platform must provide a consistent internal interface for defining and executing tests, regardless of the specific AI model being targeted. This architecture must be highly extensible to allow for the rapid addition of new AI providers as they emerge, which is critical for the platform's long-term relevance and competitive advantage.

-----

## Considered Options

### 1\. Monolithic Adapter Service

This approach involves creating a single, large service or module that contains all the specific logic for interacting with every supported AI provider. This is often implemented with a large `if/elif/else` or `switch` statement that routes requests based on the provider's name.

  * **Pros**:
      * Simple to start with for the first one or two providers.
  * **Cons**:
      * **Violates the Single Responsibility Principle**: The service becomes bloated with unrelated responsibilities.
      * **Extremely Difficult to Maintain**: As more providers are added, the codebase becomes a complex, tangled monolith.
      * **Brittle and Not Robust**: A bug in the code for one provider (e.g., a change in Anthropic's API) could crash the service and impact the availability of all other providers.
      * **High Friction for Contributions**: Adding a new provider requires modifying the core, critical service, increasing the risk of introducing regressions.

### 2\. Provider Plugin System (Adapter Pattern)

This approach involves defining a standard, abstract interface (an "Adapter" or "Plugin") for interacting with a target model. The specific logic for each individual provider is then encapsulated in a separate, self-contained "plugin" module that implements this common interface. The core application interacts only with the standard interface.

  * **Pros**:
      * **Highly Extensible and Maintainable**: Adding support for a new provider is a low-risk task that involves creating a new, self-contained plugin without modifying the core platform code.
      * **Isolation and Robustness**: Each plugin is isolated. A failure or bug in one plugin has no impact on the others.
      * **Clean Separation of Concerns**: The core orchestration engine is cleanly decoupled from the messy details of external API integrations.
      * **Adheres to SOLID Design Principles**: Promotes clean, testable, and high-quality code.

-----

## Decision

The ViolentUTF API will adopt a **Provider Plugin System**, based on the **Adapter design pattern**, to integrate with all external target AI endpoints.

1.  **Standard Interface**: A standardized **`ProviderPlugin` abstract interface** will be defined in the core application. This interface will specify a set of methods that every plugin must implement (e.g., `send_chat_completion`, `list_available_models`).
2.  **Self-Contained Plugins**: The specific logic for each AI provider (OpenAI, Anthropic, Ollama, etc.) will be implemented in its own **separate, self-contained Python module**. Each module will contain a class that inherits from and implements the `ProviderPlugin` interface.
3.  **Dynamic Loading**: The application will dynamically discover and load these plugin modules at startup.
4.  **Decoupled Interaction**: The core orchestration engine (from ADR-F1.2) will interact with these plugins only through the standardized `ProviderPlugin` interface, with no direct knowledge of any specific provider's implementation details.

-----

## Rationale

This decision establishes a clean, robust, and future-proof architecture for a core component of the platform.

1.  **Enables Rapid Extensibility**: This is the most significant advantage. The AI market is dynamic, and our ability to quickly add support for new models and providers is a critical business requirement. The plugin architecture makes this process simple, safe, and efficient.

2.  **Improves System Reliability**: By isolating provider-specific code into separate plugins, we make the entire system more robust. A breaking change in a third-party API or a bug in one plugin's implementation will not cause cascading failures across the platform.

3.  **Promotes Clean Architecture**: This design enforces a strong separation of concerns. The core platform logic remains clean and focused on orchestration, while the plugins handle the specific details of external communication. This leads to code that is easier to understand, test, and maintain.

4.  **Formalizes the "Generator" Concept**: This architecture provides the concrete engine to power the "Generator" concept used throughout the platform. A Generator, as configured by a user, will now be a configured instance of a specific provider plugin, associated with a model and a set of credentials.

-----

## Implementation Details

### `ProviderPlugin` Abstract Interface

A simplified Python example of the abstract base class that all plugins must implement:

```python
from abc import ABC, abstractmethod
from typing import List, Dict, Any

class ProviderPlugin(ABC):
    """
    Abstract interface for all AI provider integrations.
    """

    @abstractmethod
    async def send_chat_completion(
        self, messages: List[Dict[str, str]], settings: Dict[str, Any], credentials: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Sends a list of messages to the target model and returns a standardized response.
        """
        pass

    @abstractmethod
    async def list_available_models(self, credentials: Dict[str, str]) -> List[str]:
        """
        Returns a list of model names supported by this provider for the given credentials.
        """
        pass

    @abstractmethod
    async def validate_credentials(self, credentials: Dict[str, str]) -> bool:
        """
        Checks if the provided credentials are valid for authenticating with the provider.
        """
        pass
```

### Plugin Discovery

The application will discover plugins at startup by scanning a dedicated `violentutf_api/plugins/` directory. Any module in this directory that contains a class inheriting from `ProviderPlugin` will be automatically registered in a central plugin registry.

### Generator Configuration

A "Generator" stored in the database will represent a user-configurable endpoint. Its schema will include:

  * `name`: A user-friendly name (e.g., "My GPT-4 Turbo").
  * `plugin_name`: The name of the plugin to use (e.g., "openai\_plugin").
  * `model_id`: The specific model identifier for that provider (e.g., "gpt-4-turbo").
  * `credentials_id`: A foreign key to a securely stored secret (as per ADR-F4.2).

When an orchestration needs to send a prompt, it will load the generator's configuration, instantiate the correct plugin, and call its `send_chat_completion` method.

-----

## Consequences

  * **Positive**:

      * The platform is highly extensible and can adapt to changes in the AI market with minimal friction.
      * The codebase is cleaner, more robust, and easier to test due to the clear separation of concerns.
      * Onboarding new developers to add a provider is simplified, as they only need to understand the plugin interface, not the entire core platform.

  * **Negative**:

      * Requires more upfront design effort to create a stable and comprehensive `ProviderPlugin` interface. Changes to this core interface could become breaking changes for all existing plugins.
      * There is a small, typically negligible, performance overhead associated with the dynamic loading and indirection of the plugin system.

  * **Technical Impact**:

      * A core `ProviderPlugin` abstract base class must be designed and implemented.
      * A plugin discovery and registration mechanism is required at application startup.
      * All existing provider-specific integration code must be refactored into separate plugin modules.
      * The database schema for "Generators" must be updated to support this architecture.

-----

## Related Artifacts/Decisions

  * **ADR-F1.2: Server-Side Orchestration**: The orchestration engine is the primary consumer of this plugin architecture. It uses the `ProviderPlugin` interface to send prompts to targets.
  * **ADR-F4.2: Secrets Management**: This decision is tightly coupled with the secrets management strategy, as each plugin will require secure credentials to be retrieved and passed to it during initialization.
