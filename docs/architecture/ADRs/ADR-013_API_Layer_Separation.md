# ADR-013: API Layer Database Separation and Service Layer Integration

## Status
Accepted

## Authors
Claude Code (AI Assistant) - Implementation Support
Cybonto (Technical Lead)

## Date
2025-08-25

## Stakeholders
* API Development Team (Primary)
* Architecture Review Board
* Quality Assurance Team
* DevOps/Platform Operations Team
* Security Team

## Context

The ViolentUTF API currently has significant architectural violations where API endpoint functions directly interact with database sessions, performing commit and rollback operations within the presentation layer. This violates the separation of concerns principle and creates multiple architectural and maintainability issues:

### Current Violations
- **19 API endpoint files** contain direct `AsyncSession = Depends(get_db*)` dependencies
- **38+ direct database operations** including `session.commit()`, `session.rollback()`, `db.commit()`, `db.rollback()`
- **PyTestArch compliance violations** flagged by architectural fitness functions
- **Transaction boundary ambiguity** with business logic mixed into presentation layer
- **Testing complexity** due to tight coupling between API endpoints and database layer

### Affected Files
- `app/api/endpoints/users.py` (12 violations)
- `app/api/endpoints/roles.py` (11 violations)
- `app/api/endpoints/api_keys.py` (7 violations)
- `app/api/endpoints/architectural_metrics.py` (3 violations)
- `app/api/endpoints/mfa_policies.py` (5 violations)
- Additional 14 endpoint files with similar patterns

### Technical Debt Impact
- **Maintainability**: Database logic scattered across presentation layer
- **Testability**: Unit testing requires database setup and transaction management
- **Reusability**: Business logic cannot be reused outside HTTP context
- **Performance**: Unclear transaction boundaries may lead to inefficient database usage
- **Security**: Direct database access increases attack surface

## Considered Options

### 1. Gradual Refactoring with Backward Compatibility
Incrementally move database operations to service layer while maintaining existing API contracts.

**Pros:**
- Minimal risk of breaking existing integrations
- Can be done incrementally over multiple releases
- Maintains all existing HTTP response formats and status codes

**Cons:**
- Extended timeline with architectural violations remaining
- Potential for inconsistent patterns during transition
- May require duplicate code during transition period

### 2. Complete API Layer Redesign
Completely redesign API endpoints with new contracts and eliminate all direct database access.

**Pros:**
- Clean architectural separation from the start
- Opportunity to improve API design patterns
- Eliminates all technical debt immediately

**Cons:**
- **Breaking changes** for existing API clients
- Significant risk of service disruption
- Requires coordination with all downstream consumers

### 3. Service Layer Facade with Preserved Contracts
Implement service layer behind existing API contracts, eliminating direct database access while preserving all existing endpoint signatures and response formats.

**Pros:**
- **Zero breaking changes** for API consumers
- Clean architectural separation
- Improved testability and maintainability
- Clear transaction boundaries

**Cons:**
- Requires careful mapping between service layer and API layer
- May need temporary adapter patterns during transition

## Decision

The ViolentUTF API will adopt **Option 3: Service Layer Facade with Preserved Contracts**.

### Core Architectural Principles

1. **API Layer Responsibility**: HTTP request/response handling, input validation, authentication/authorization, response serialization
2. **Service Layer Responsibility**: Business logic, transaction management, database operations, cross-cutting concerns
3. **Dependency Direction**: API layer depends on service layer, never the reverse
4. **Contract Preservation**: All existing HTTP endpoints maintain identical signatures and response formats

### Implementation Strategy

1. **Service Layer Integration**: API endpoints will use FastAPI dependency injection to access service layer components
2. **Transaction Management**: All database transactions managed within service layer methods
3. **Error Handling**: Service layer exceptions mapped to appropriate HTTP status codes
4. **Response Formatting**: API layer handles serialization of service layer responses to HTTP format
5. **Authentication/Authorization**: Maintained in API layer, passed to service layer as context

## Rationale

### Technical Benefits
1. **Architectural Compliance**: Eliminates PyTestArch violations and establishes proper layer separation
2. **Improved Testability**: Service layer can be unit tested without HTTP/database setup
3. **Better Performance**: Clearer transaction boundaries enable optimized database access patterns
4. **Enhanced Security**: Reduced database access surface area in presentation layer
5. **Code Reusability**: Business logic can be reused across different interfaces (API, CLI, background tasks)

### Business Benefits
1. **Zero Downtime Migration**: No breaking changes for existing API consumers
2. **Faster Development**: Clear separation enables parallel development of API and business logic
3. **Reduced Maintenance Cost**: Centralized business logic reduces code duplication
4. **Quality Improvement**: Better testability leads to higher code coverage and fewer bugs

### Risk Mitigation
1. **Gradual Migration**: High-priority endpoints first, followed by medium and low priority
2. **Comprehensive Testing**: Integration tests verify API contract preservation
3. **Performance Monitoring**: Benchmark endpoints to ensure <5% latency increase
4. **Rollback Plan**: Maintain ability to restore direct database access patterns if needed

## Implementation Details

### Service Layer Dependency Injection Pattern
```python
# Before (Direct Database Access)
async def create_user(
    request: Request,
    user_data: UserCreate,
    session: AsyncSession = Depends(get_db_dependency)
):
    # Direct database operations
    await session.commit()

# After (Service Layer Integration)
async def create_user(
    request: Request,
    user_data: UserCreate,
    user_service: UserService = Depends(get_user_service)
):
    # Service layer handles all database operations
    return await user_service.create_user(user_data, user_context)
```

### FastAPI Dependency Configuration
Update `app/api/deps.py` to provide service layer dependencies:
```python
def get_user_service() -> UserService:
    return UserService()

def get_api_key_service() -> APIKeyService:
    return APIKeyService()
```

### Error Handling Pattern
```python
try:
    result = await service.perform_operation(data)
    return ResponseModel(result)
except ServiceValidationError as e:
    raise HTTPException(status_code=400, detail=str(e))
except ServiceNotFoundError as e:
    raise HTTPException(status_code=404, detail=str(e))
```

## Consequences

### Positive Impacts
- **Architectural Compliance**: Zero PyTestArch violations in API layer
- **Improved Testability**: Clean unit testing for both API and service layers
- **Enhanced Maintainability**: Clear separation of concerns and reduced coupling
- **Better Performance**: Optimized transaction boundaries and database access patterns
- **Increased Reliability**: Centralized error handling and transaction management

### Potential Challenges
- **Development Complexity**: Initial learning curve for service layer patterns
- **Performance Overhead**: Additional layer of indirection (target: <5% latency increase)
- **Service Layer Completeness**: Ensure all necessary services are available and feature-complete

### Technical Impact
- **Codebase Changes**: 19 API endpoint files require refactoring
- **Testing Updates**: Integration tests must verify API contract preservation
- **Documentation**: Update API documentation to reflect service layer architecture
- **Monitoring**: Add performance monitoring for service layer interactions

### Operational Impact
- **Deployment Strategy**: Blue-green deployment to minimize risk
- **Monitoring Requirements**: Enhanced observability for service layer performance
- **Team Training**: Development team education on service layer patterns

## Validation Criteria

### Pre-Implementation
- [ ] All required services exist and are feature-complete
- [ ] Service layer unit tests achieve >90% coverage
- [ ] Performance baseline established for all affected endpoints

### During Implementation
- [ ] Zero direct `AsyncSession` dependencies in API endpoint functions
- [ ] Zero direct database commit/rollback operations in API layer
- [ ] All API integration tests pass with unchanged contracts

### Post-Implementation
- [ ] PyTestArch architectural fitness tests pass with zero violations
- [ ] API response formats and status codes remain unchanged
- [ ] Performance impact remains under 5% latency increase
- [ ] All security tests pass with no regressions

## Related Artifacts/Decisions

- **ADR-F1-3: Endpoint Integration Architecture**: Provides plugin architecture patterns applicable to service integration
- **ADR-008: Logging and Auditing**: Service layer must maintain audit capabilities
- **ADR-009: Error and Responses**: Error handling patterns between service and API layers
- **Issue #85**: Repository pattern implementations that support this service layer architecture
- **Issue #69-1**: Service layer refactoring that this API cleanup depends upon

## Success Metrics

1. **Architectural Compliance**: 0 PyTestArch violations in API layer
2. **API Compatibility**: 100% preservation of existing API contracts
3. **Performance Impact**: <5% increase in endpoint response times
4. **Test Coverage**: >90% service layer unit test coverage
5. **Integration Success**: All API integration tests pass without modification
