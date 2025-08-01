# ADR-003: Hybrid Authorization Model using RBAC and ABAC

## Status

Accepted

## Authors

Tam Nguyen (Cybonto)

## Date

2025-07-27

## Stakeholders

  * API Development Team
  * Consumers of the API (Internal Teams, External Government Agencies, CI/CD Systems)
  * GSA Compliance and Security Team
  * Platform Operations Team

## Context

Following the decision to implement a self-contained authentication system using JWTs and API Keys (ADR-002), we must now define the model that governs *what* an authenticated principal is allowed to do. Authentication answers "who you are," while authorization answers "what you are allowed to do."

For a multi-tenant AI red teaming platform, a granular and rigorously enforced authorization model is non-negotiable. The system will store sensitive test configurations, target credentials, and vulnerability data belonging to different organizations. A failure in the authorization logic could lead to catastrophic data breaches and a complete loss of trust in the platform.

This decision directly mitigates several of the most critical OWASP API Security risks:

  * **API1:2023 - Broken Object Level Authorization**: Ensuring a user from Organization A cannot access resources belonging to Organization B.
  * **API5:2023 - Broken Function Level Authorization**: Ensuring a user with a 'viewer' role cannot perform actions reserved for an 'admin' role.
  * **API3:2023 - Broken Object Property Level Authorization**: Ensuring a user cannot change specific fields on an object they don't have permission to modify.

-----

## Considered Options

### 1\. Role-Based Access Control (RBAC) Only

In this model, permissions are associated with roles (e.g., `admin`, `tester`, `viewer`), and users are assigned one or more roles. The API would check if the user's role has permission to call a specific endpoint.

  * **Pros**:
      * Simple to understand, implement, and manage for broad permission structures.
      * Effectively addresses Broken Function Level Authorization.
  * **Cons**:
      * **Insufficient for Multi-Tenancy**: RBAC is often too coarse-grained to handle data ownership. It can confirm a user is a `tester`, but it cannot easily confirm they are the *owner* of the specific resource they are trying to access. This leaves a significant gap in preventing Broken Object Level Authorization.

### 2\. Attribute-Based Access Control (ABAC) Only

In this model, access decisions are governed by policies that evaluate attributes of the user, the resource being accessed, and the environment. It is a highly powerful and flexible model.

  * **Pros**:
      * Extremely granular and expressive, allowing for complex rules (e.g., "allow if user.org\_id == resource.org\_id").
      * Future-proof and can adapt to new requirements without changing the core model.
  * **Cons**:
      * **High Implementation Complexity**: Designing, implementing, and debugging a full-fledged ABAC policy engine can be a massive undertaking, potentially delaying the project.
      * **Potential for Errors**: Complex policies can be difficult to reason about, potentially leading to misconfigurations that create security holes.

### 3\. Hybrid RBAC + ABAC Model

This approach uses both models in a layered fashion. RBAC is used for broad, function-level checks, while ABAC is used for fine-grained, resource-specific ownership checks.

  * **Pros**:
      * **Best of Both Worlds**: Combines the simplicity of RBAC for managing general capabilities with the power of ABAC for enforcing strict data isolation.
      * **Layered Security**: Provides defense-in-depth. A request must pass both a role check *and* an attribute check.
      * **Manageable Complexity**: The implementation can be pragmatic. The RBAC layer is straightforward, and the ABAC layer can start with a simple, critical rule (like checking `organization_id`) and evolve from there.

-----

## Decision

The ViolentUTF API will implement a **hybrid authorization model** that combines Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC).

1.  **RBAC** will be used to control access to API functionalities at the endpoint level (Function-Level Authorization).
2.  **ABAC** will be used to enforce data ownership and control access to specific data resources (Object-Level Authorization), primarily based on the tenant or organization.

-----

## Rationale

This hybrid model was chosen as it provides the most comprehensive and secure solution while remaining practical to implement.

1.  **Directly Addresses All Critical Authorization Risks**: This layered approach provides a complete solution. RBAC effectively prevents users from accessing entire classes of functionality they shouldn't (solving `API5`), while the ABAC layer ensures that even when a user has the right role, they can only access data belonging to them (solving `API1`). This defense-in-depth is critical for a multi-tenant, security-focused platform.

2.  **Enables Secure Multi-Tenancy from Day One**: The core requirement of a shared platform is strict data isolation between tenants. A simple RBAC model is insufficient for this. By including ABAC from the start, we ensure that the architecture is fundamentally built around the principle of data ownership, which is essential for GSA compliance and user trust.

3.  **Leverages the Authentication Strategy**: This decision is a natural extension of ADR-002. The JWTs are designed to carry claims for both `roles` and `organization_id`. The hybrid model makes direct and efficient use of these claims: the `roles` array feeds the RBAC checks, and the `organization_id` attribute feeds the ABAC checks. This creates a highly coherent and tightly integrated security system.

4.  **Provides Pragmatic Extensibility**: The model is powerful yet manageable. We can define a small, clear set of roles initially. The ABAC logic can be implemented as a simple, reusable dependency that checks for matching `organization_id` on all data access queries. This provides immense security value without the overhead of building a complex, abstract policy engine.

-----

## Implementation Details

  * **JWT Claims**: The authorization system will rely on the following claims from the JWT, as defined in ADR-002:

      * `sub`: The unique identifier for the user principal.
      * `roles`: An array of strings representing the user's roles (e.g., `["tester", "viewer"]`).
      * `organization_id`: A UUID representing the user's tenant or organization.

  * **RBAC Implementation**:

      * **Initial Roles**: A preliminary set of roles will be defined:
          * `viewer`: Can read non-sensitive data (e.g., list their own tests, read results).
          * `tester`: Can perform all `viewer` actions plus create and execute new red teaming tests.
          * `admin`: Can perform all `tester` actions plus manage users and settings within their own organization.
      * **Enforcement**: RBAC checks will be implemented as a reusable FastAPI dependency (decorator). For example: `app.post("/scans", dependencies=[Depends(require_role("tester"))])`.

  * **ABAC Implementation**:

      * **Primary Attribute**: The `organization_id` will be the primary attribute for data isolation.
      * **Database Schema**: Every database table that stores tenant-owned resources (e.g., `tests`, `results`, `targets`) **must** have a non-nullable `organization_id` column.
      * **Enforcement**: Logic will be embedded into data repository/service layers. When fetching a resource, the query will *always* be filtered by the `organization_id` from the user's token. For example:
        ```python
        # Pseudocode for fetching a resource
        def get_test_by_id(test_id: UUID, current_user: User):
            # The query itself ensures we only look within the user's organization
            db_query = "SELECT * FROM tests WHERE id = :test_id AND organization_id = :org_id"
            result = db.execute(db_query, {"test_id": test_id, "org_id": current_user.organization_id})

            # If the result is null, the object either doesn't exist or belongs to another tenant.
            # Returning 404 is a security best practice to avoid leaking information.
            if not result:
                raise HTTPException(status_code=404, detail="Resource not found")
            return result
        ```

-----

## Consequences

  * **Positive**:

      * Provides a robust, multi-layered security model that is highly defensible and auditable.
      * The architecture is secure against the most common and severe API authorization vulnerabilities by design.
      * The model is clear to developers: check the role for the function, then check ownership for the data.

  * **Negative**:

      * Increases implementation complexity compared to a simple RBAC-only system.
      * Requires strict developer discipline to ensure that *every* data-accessing endpoint correctly applies both the RBAC and ABAC checks. A single omission could create a vulnerability.

  * **Technical Impact**:

      * A standardized set of reusable FastAPI dependencies must be created for performing role and attribute checks to ensure consistency.
      * The database schema for all tenant-owned resources is now required to include an `organization_id` foreign key.
      * Unit and integration tests must be written to explicitly verify both positive and negative authorization cases (e.g., test that a user *cannot* access data from another organization).

-----

## Related Artifacts/Decisions

  * **ADR-002: Phased Authentication Strategy using JWT and API Keys**: This ADR directly consumes the identity and claims established in the authentication strategy.
  * **Database Schema Design**: This decision heavily influences the required structure of the database, mandating the inclusion of ownership metadata on all relevant tables.
