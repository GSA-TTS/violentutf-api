# ViolentUTF API Dependency Analysis Report

Generated on: 2025-09-19T14:47:18.371749
Analysis Duration: 0.16 seconds

## Executive Summary

This comprehensive dependency analysis covers all layers of the ViolentUTF API system:

- **Services**: 6 Docker services analyzed
- **Repositories**: 28 repository classes analyzed
- **Configurations**: 80 configuration parameters analyzed

## Service Dependencies

### Critical Services
- api
- db

### Service Types Distribution
- application: 1
- database: 1
- cache: 1
- worker: 1
- monitoring: 1
- reverse_proxy: 1

## Repository Analysis

- **Total Repositories**: 28
- **Total Models**: 27
- **Model Relationships**: 155
- **Average Complexity**: 29.21
- **Most Complex Repository**: EnhancedRepository

## Configuration Analysis

- **Total Configurations**: 80
- **Required Configurations**: 1

## Risk Assessment

### Single Points of Failure
- Service: db (depended on by 2 services)
- Service: redis (depended on by 3 services)
- Critical database: db

### Complex Repositories
- UserRepository
- RoleRepository
- APIKeyRepository
- EnhancedRepository
- BaseRepository
- AuditLogRepository
- SecurityScanRepository

## Recommendations

1. Refactor high-complexity repositories: RoleRepository, EnhancedRepository, BaseRepository, AuditLogRepository, SecurityScanRepository
2. Implement dependency health monitoring with automated alerts
3. Create dependency change impact assessment procedures
4. Establish regular dependency review and optimization cycles
5. Document dependency failure scenarios and recovery procedures

## Dependency Graphs

The following dependency graphs have been generated:

- **Service**: `/Users/tamnguyen/Documents/GitHub/violentutf-api/docs/dependencies/service_dependencies.mmd`
- **Application**: `/Users/tamnguyen/Documents/GitHub/violentutf-api/docs/dependencies/application_dependencies.mmd`
- **Database**: `/Users/tamnguyen/Documents/GitHub/violentutf-api/docs/dependencies/database_dependencies.mmd`

## Analysis Completeness

- static_analysis: ✓
- repository_analysis: ✓
- runtime_analysis: ✗
- graph_generation: ✓

---

*This report was generated automatically by the ViolentUTF API Dependency Analysis Tool v1.0.0*
