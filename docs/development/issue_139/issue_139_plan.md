# Issue #139 Implementation Plan - Code Deduplication and Shared Utilities

## Executive Summary

This implementation plan addresses Epic #117's code deduplication objective by creating shared utilities and standardizing common patterns across 11+ automation scripts, targeting a 25% codebase size reduction while improving maintainability and consistency.

## Problem Analysis

### Identified Code Duplication Patterns

1. **Logging Setup Duplication (15 scripts)**
   - Mixed use of `logging.getLogger(__name__)` and `structlog.get_logger(__name__)`
   - Inconsistent logging configuration across scripts
   - Files affected: All automation scripts in `scripts/` and `tools/`

2. **File I/O Operation Repetition (8 scripts)**
   - Repeated patterns of `with open()`, `json.load()`, `json.dump()`
   - Inconsistent error handling for file operations
   - No standardized path validation or atomic operations

3. **Exception Handling Patterns (12 scripts)**
   - Similar try/catch blocks with basic error logging
   - No standardized error context management
   - Inconsistent error reporting formats

4. **Configuration Management Duplication (6 scripts)**
   - Multiple scripts reading settings independently
   - No shared validation or environment override patterns

### Large Method Complexity Issues

1. **data_asset_inventory.py**: `_analyze_access_patterns()` (lines 373-420, 47 lines)
2. **backup_coverage_audit.py**: `discover_repositories()` (lines 145-205, 60 lines)

## Implementation Strategy

### Phase 1: Shared Utilities Library Creation

#### 1.1 Core Library Structure
```
audit_utils/
├── __init__.py
├── logging.py          # Standardized logging setup
├── exceptions.py       # Exception hierarchy and handling
├── file_operations.py  # Secure file I/O operations
├── config.py          # Configuration management
└── testing.py         # Testing utilities
```

#### 1.2 Logging Utilities (`audit_utils/logging.py`)

**Objective**: Unify logging across all automation scripts

**Key Features**:
- Standardized structlog configuration
- Consistent log formatting
- Sensitive data sanitization
- Environment-based log levels

**API Design**:
```python
def setup_audit_logger(name: str, level: str = "INFO") -> structlog.Logger
def log_audit_event(event_type: str, **context) -> None
def sanitize_log_data(data: Dict[str, Any]) -> Dict[str, Any]
```

#### 1.3 Exception Handling (`audit_utils/exceptions.py`)

**Objective**: Standardize error handling patterns

**Key Features**:
- Audit-specific exception hierarchy
- Context-aware error decorators
- Consistent error reporting

**API Design**:
```python
class AuditError(Exception): pass
class ConfigurationError(AuditError): pass
class ValidationError(AuditError): pass

def audit_error_handler(func: Callable) -> Callable  # Decorator
def create_error_context(**context) -> Dict[str, Any]
```

#### 1.4 File Operations (`audit_utils/file_operations.py`)

**Objective**: Secure, consistent file I/O operations

**Key Features**:
- Atomic file operations
- JSON validation and sanitization
- Path security validation
- Backup and recovery

**API Design**:
```python
def safe_read_json(path: Path) -> Dict[str, Any]
def safe_write_json(path: Path, data: Dict[str, Any]) -> None
def atomic_file_operation(path: Path, operation: Callable) -> Any
def validate_file_path(path: Path, allowed_dirs: List[Path]) -> bool
```

#### 1.5 Configuration Management (`audit_utils/config.py`)

**Objective**: Centralized configuration handling

**Key Features**:
- Shared settings validation
- Environment-specific overrides
- Configuration caching

**API Design**:
```python
class AuditConfig:
    def get_database_config() -> DatabaseConfig
    def get_logging_config() -> LoggingConfig
    def get_security_config() -> SecurityConfig
    def validate_configuration() -> bool
```

### Phase 2: Method Decomposition

#### 2.1 Data Asset Inventory Refactoring

**Current Issue**: `_analyze_access_patterns()` method (47 lines, multiple responsibilities)

**Refactoring Strategy**:
```python
def _analyze_access_patterns(self, repository_data, schema_data) -> Dict[str, Any]:
    patterns = self._extract_repository_patterns(repository_data)
    crud_analysis = self._analyze_crud_patterns(repository_data)
    api_mappings = self._analyze_api_patterns(repository_data)
    return self._compile_access_analysis(patterns, crud_analysis, api_mappings)

def _extract_repository_patterns(self, data) -> Dict[str, Any]: pass
def _analyze_crud_patterns(self, data) -> Dict[str, Any]: pass
def _analyze_api_patterns(self, data) -> Dict[str, Any]: pass
def _compile_access_analysis(self, *analyses) -> Dict[str, Any]: pass
```

#### 2.2 Backup Coverage Audit Refactoring

**Current Issue**: `discover_repositories()` method (60 lines, complex fallback logic)

**Refactoring Strategy**:
```python
class RepositoryDiscoveryStrategy:
    def discover_from_container(self) -> List[RepositoryInfo]: pass
    def discover_from_fallback(self) -> List[RepositoryInfo]: pass
    def discover_from_configuration(self) -> List[RepositoryInfo]: pass

def discover_repositories(self) -> List[RepositoryInfo]:
    strategies = [
        self.discovery_strategy.discover_from_container(),
        self.discovery_strategy.discover_from_fallback(),
        self.discovery_strategy.discover_from_configuration()
    ]
    return self._consolidate_discoveries(strategies)
```

### Phase 3: Migration Strategy

#### 3.1 Incremental Migration Approach

1. **Week 1**: Create shared utilities library with full test coverage
2. **Week 2**: Migrate logging utilities (5 highest-impact scripts)
3. **Week 3**: Migrate file operations and configuration management
4. **Week 4**: Complete method decomposition and final migrations

#### 3.2 Migration Validation

- Before/after line count comparison
- Functionality preservation testing
- Performance regression testing
- Security validation

## Test-Driven Development Approach

### Testing Strategy

1. **Shared Utilities Testing**
   - Unit tests for each utility module (100% coverage)
   - Integration tests for file operations
   - Performance benchmarks for refactored methods

2. **Migration Testing**
   - Functionality preservation tests
   - Backward compatibility validation
   - Error handling scenario testing

### Test Structure
```
tests/unit/audit_utils/
├── test_logging.py
├── test_exceptions.py
├── test_file_operations.py
└── test_config.py

tests/integration/
├── test_shared_utilities_integration.py
└── test_migration_validation.py
```

## Success Metrics

### Code Quality Metrics
- **Lines of Code Reduction**: Target 25% (baseline measurement required)
- **Cyclomatic Complexity**: Reduce methods >10 complexity to <5
- **Code Duplication**: Eliminate identified repetitive patterns
- **Test Coverage**: Maintain 100% for shared utilities

### Maintainability Metrics
- **Change Impact**: Reduce maintenance overhead by 40%
- **Consistency Score**: 100% adoption of shared utilities
- **Error Rate**: Standardized error handling across all scripts

## Risk Mitigation

### Technical Risks
1. **Functionality Regression**: Comprehensive test suite before migration
2. **Performance Impact**: Benchmark critical paths
3. **Integration Complexity**: Incremental rollout with validation

### Mitigation Strategies
- Feature flag approach for gradual rollout
- Automated rollback capabilities
- Comprehensive integration testing
- Code review gates for all changes

## Implementation Timeline

### Week 1: Foundation
- [ ] Create audit_utils library structure
- [ ] Implement logging utilities with tests
- [ ] Implement exception handling with tests

### Week 2: Core Utilities
- [ ] Implement file operations utilities with tests
- [ ] Implement configuration management with tests
- [ ] Complete shared utilities documentation

### Week 3: Method Decomposition
- [ ] Refactor data_asset_inventory.py methods
- [ ] Refactor backup_coverage_audit.py methods
- [ ] Performance validation and optimization

### Week 4: Migration and Validation
- [ ] Migrate all 11+ automation scripts
- [ ] Final testing and validation
- [ ] Documentation and training materials

## Definition of Done

### Technical Requirements
- [ ] audit_utils library created with 100% test coverage
- [ ] All identified duplication patterns eliminated
- [ ] All methods under 30 lines with single responsibility
- [ ] 25% codebase size reduction achieved
- [ ] All automation scripts use shared utilities
- [ ] No functionality regression in any script

### Quality Assurance
- [ ] All tests pass (unit, integration, performance)
- [ ] Code review approved
- [ ] Security validation completed
- [ ] Documentation updated and reviewed

### Deliverables
- [ ] Shared utilities library (`audit_utils/`)
- [ ] Refactored automation scripts
- [ ] Comprehensive test suite
- [ ] Migration documentation
- [ ] Performance and quality metrics report

## Conclusion

This implementation plan provides a systematic approach to eliminating code duplication while maintaining functionality and improving code quality. The phased approach ensures minimal risk while achieving significant maintainability improvements.

The shared utilities library will serve as a foundation for future automation script development, enforcing consistent patterns and reducing development overhead.
