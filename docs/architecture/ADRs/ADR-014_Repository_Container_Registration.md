# ADR-014: Repository Container Registration and Lifecycle Management

## Status
Proposed

## Context
The ViolentUTF API currently has 8 repository implementations that need proper registration and lifecycle management within the dependency injection container. The existing system requires:

- Manual instantiation of repositories in each service
- Direct dependency on database sessions in service constructors
- No centralized repository health monitoring
- Complex dependency management in FastAPI startup
- Inconsistent repository lifecycle across different components

Current challenges:
- Repository instances are created ad-hoc in service dependencies
- No unified approach to repository initialization and cleanup
- Health checks cannot validate repository connectivity
- Testing is complicated due to scattered repository instantiation
- Dependency injection container lacks complete repository registration

The system currently supports 8 repository interfaces: `IUserRepository`, `IApiKeyRepository`, `ISessionRepository`, `IAuditRepository`, `ISecurityScanRepository`, `IVulnerabilityRepository`, `IRoleRepository`, and `IHealthRepository`.

## Decision
Implement centralized repository registration within the dependency injection container with proper lifecycle management during FastAPI application startup and shutdown.

Key components:
1. **Repository Factory Pattern**: Create factory functions for each repository with proper error handling
2. **Container Registration**: Register all 8 repository implementations in the DI container during startup
3. **Dependency Injection**: Provide FastAPI dependency functions that resolve repositories from the container
4. **Health Monitoring**: Integrate repository health checks into system health endpoints
5. **Session Management**: Implement proper database session lifecycle for repository instances

## Alternatives

### Alternative 1: Continue Direct Instantiation
- Keep current pattern of creating repositories directly in service dependencies
- **Rejected**: Leads to scattered instantiation, difficult testing, no centralized health monitoring

### Alternative 2: Service Locator Pattern
- Use a service locator to retrieve repositories
- **Rejected**: Creates hidden dependencies, violates dependency inversion principle

### Alternative 3: Factory Pattern Without Container
- Create factories without centralized container registration
- **Rejected**: Misses benefits of centralized lifecycle management and health monitoring

## Consequences

### Positive
- **Centralized Management**: All repository lifecycle managed in one place
- **Health Monitoring**: Repository connectivity can be monitored and reported
- **Testability**: Easy to mock repositories through container registration
- **Consistency**: Uniform approach to repository creation and management
- **Performance**: Repository instances can be cached and reused appropriately
- **Error Handling**: Centralized error handling for repository initialization failures

### Negative
- **Initial Complexity**: More upfront configuration required
- **Startup Dependencies**: Application startup becomes more complex with repository initialization
- **Container Coupling**: Services become dependent on container registration patterns

### Neutral/Trade-offs
- **Memory Usage**: Repository instances may consume more memory if cached
- **Configuration**: Requires careful configuration for different environments (dev/test/prod)

## Rationale
This decision addresses the core issue raised in Issue 87 by:

1. **Completing Container Registration**: All 8 repositories will be properly registered in the DI container
2. **Startup Integration**: Repository initialization becomes part of the FastAPI lifecycle
3. **Health Monitoring**: System health endpoints can report repository status
4. **Testing Support**: Easier test setup with container-based dependency injection
5. **ADR Compliance**: Aligns with ADR-013 (Repository Pattern) for proper data access abstraction

The factory pattern provides flexibility for repository creation while the container ensures centralized management. Health checks enable monitoring and alerting on repository connectivity issues.

## Implementation Notes
- Repository factories will include connection validation and retry logic
- Health checks will test actual database connectivity, not just object instantiation
- FastAPI dependency functions will resolve repositories from the container with proper error handling
- Database sessions will be properly scoped and managed throughout repository lifecycles

## References
- ADR-013: Repository Pattern - Establishes repository abstraction patterns
- ADR-002: Authentication - Dependencies on user and session repositories
- FastAPI Dependency Injection Documentation
- SQLAlchemy Session Management Best Practices

## Date
2025-08-26

## Authors
Claude Code (AI Assistant)
