# ViolentUTF API Extraction & Spinoff Strategy

## Executive Summary

This document outlines the strategic plan for extracting the ViolentUTF API from the mother repository (`violentutf`) to create a parallel, standalone repository (`violentutf-api`). Unlike a migration, this extraction will maintain both repositories in active development, allowing the API to evolve independently while preserving its presence in the mother repository for integrated development and testing.

The extracted API will operate as a fully standalone service without dependencies on APISIX, Keycloak, or other ViolentUTF components. As an official GSA repository, it will maintain higher code quality standards and may support components not present in the mother ViolentUTF stack.

## Table of Contents

1. [Current State Analysis](#current-state-analysis)
2. [Extraction Goals](#extraction-goals)
3. [Extraction Strategy](#extraction-strategy)
4. [Pre-Extraction Checklist](#pre-extraction-checklist)
5. [Extraction Steps](#extraction-steps)
6. [Post-Extraction Setup](#post-extraction-setup)
7. [Synchronization Strategy](#synchronization-strategy)
8. [Risk Assessment](#risk-assessment)
9. [Timeline](#timeline)
10. [Ongoing Maintenance](#ongoing-maintenance)

## Current State Analysis

### Repository Structure
The API code currently resides in the `violentutf_api/` directory within the mother repository:

```
violentutf/
├── violentutf_api/
│   ├── fastapi_app/
│   │   ├── app/
│   │   │   ├── api/endpoints/
│   │   │   ├── core/
│   │   │   ├── db/migrations/
│   │   │   ├── exceptions/
│   │   │   └── mcp/
│   │   ├── app_data/
│   │   ├── requirements*.txt
│   │   ├── Dockerfile*
│   │   └── .env.template
│   ├── migrations/
│   └── docker-compose.yml
├── tests/
│   ├── api_tests/
│   └── test_*api*.py
├── apisix/           # API Gateway configuration
└── Various API-related scripts
```

### Key Findings
1. **Framework**: FastAPI-based application
2. **Dependencies**: Self-contained requirements files
3. **Database**: Migration system already in place
4. **Docker**: Fully dockerized with multiple configurations
5. **Testing**: Mix of API-specific and integrated tests
6. **Gateway**: APISIX integration for API management

## Extraction Goals

### Primary Objectives
1. **Standalone Operation**: Create fully self-contained API without APISIX/Keycloak dependencies
2. **GSA Compliance**: Meet official GSA repository standards for code quality and security
3. **Independent Evolution**: Support components and technologies not in mother ViolentUTF stack
4. **Enhanced Quality**: Implement stricter code review, testing, and documentation standards
5. **Specialized CI/CD**: Deploy API-specific pipelines with government compliance checks
6. **Preserve Integration**: Maintain API in mother repo for backward compatibility testing

### Success Criteria
- [ ] Standalone API repository is fully functional
- [ ] Mother repository continues to work unchanged
- [ ] Clear synchronization process is established
- [ ] Both repositories can be developed independently
- [ ] Integration points are well-documented

## Architectural Differences

### Standalone Architecture
The extracted API will differ significantly from the mother repository version:

1. **No External Dependencies**
   - Runs without APISIX gateway
   - Independent authentication (no Keycloak required)
   - Self-contained rate limiting
   - Direct API access on standard ports

2. **Simplified Deployment**
   - Single service deployment
   - Minimal infrastructure requirements
   - Cloud-native ready
   - Container-first approach

3. **Enhanced Security**
   - Built-in authentication/authorization
   - GSA-compliant security controls
   - Enhanced audit logging
   - Automated security scanning

### Future Technology Stack
The standalone API may adopt technologies not present in the mother repository:

1. **Modern Components**
   - Different authentication providers
   - Alternative database systems
   - New caching strategies
   - Cloud-specific services

2. **Government Standards**
   - FedRAMP compliance tools
   - FISMA security controls
   - Accessibility standards
   - Performance benchmarks

## Extraction Strategy

### Approach: Copy with History Preservation

We will use a **selective extraction** approach that:
1. Preserves git history for API-related files
2. Maintains the API code in the mother repository
3. Establishes a clear baseline for future synchronization
4. Allows for independent evolution of both codebases

### Why Not Fork?
- A fork implies the entire repository, not just the API
- Forking creates unnecessary overhead
- We want a clean, API-only repository structure

## Pre-Extraction Checklist

### 1. Analysis Phase
- [ ] Document all API endpoints and their dependencies
- [ ] Identify shared utilities that need copying
- [ ] List integration points with mother repo
- [ ] Document environment variables and configurations
- [ ] Map all external service dependencies

### 2. Planning Phase
- [ ] Define synchronization strategy
- [ ] Establish versioning approach
- [ ] Plan branching strategy for both repos
- [ ] Document team responsibilities
- [ ] Create communication protocols

### 3. Technical Preparation
- [ ] Ensure all API tests can run independently
- [ ] Document API-specific deployment process
- [ ] Prepare standalone documentation
- [ ] Plan monitoring and logging strategy
- [ ] Review security considerations

## Extraction Steps

### Phase 1: Repository Preparation (Day 1)

1. **Create extraction workspace**
   ```bash
   mkdir violentutf-extraction
   cd violentutf-extraction

   # Clone mother repository
   git clone https://github.com/GSA-TTS/violentutf.git
   ```

2. **Create history-preserved extraction**
   ```bash
   # Clone again for extraction
   git clone https://github.com/GSA-TTS/violentutf.git violentutf-api-extract
   cd violentutf-api-extract

   # Use git filter-repo to extract with history
   git filter-repo \
     --path violentutf_api/ \
     --path tests/api_tests/ \
     --path tests/test_orchestrator_api.py \
     --path tests/test_unit_api_endpoints.py \
     --path tests/test_apisix_integration.py
   ```

### Phase 2: Repository Restructuring (Day 2)

1. **Reorganize directory structure**
   ```bash
   # Flatten the structure
   mv violentutf_api/fastapi_app/* .
   mv violentutf_api/migrations ./migrations
   mv violentutf_api/docker-compose.yml ./docker-compose.yml

   # Move tests to appropriate location
   mkdir -p tests/integration
   mv tests/api_tests/* tests/
   mv tests/test_*api*.py tests/integration/

   # Clean up empty directories
   rm -rf violentutf_api
   find . -type d -empty -delete
   ```

2. **Update import paths**
   ```bash
   # Update Python imports
   find . -name "*.py" -type f -exec sed -i '' \
     -e 's/from violentutf_api\.fastapi_app/from/g' \
     -e 's/import violentutf_api\.fastapi_app/import/g' \
     {} +
   ```

### Phase 3: Standalone Configuration (Day 3)

1. **Create root configuration files**
   ```bash
   # Copy requirements to root
   cp requirements*.txt ./

   # Create project files
   touch README.md
   touch CHANGELOG.md
   touch .env.example
   ```

2. **Update Docker configuration**
   - Adjust Dockerfile paths
   - Update docker-compose.yml volumes
   - Fix working directory references

3. **Initialize new repository**
   ```bash
   git remote remove origin
   git remote add origin https://github.com/GSA-TTS/violentutf-api.git
   git branch -M main
   ```

### Phase 4: Validation (Day 4)

1. **Test standalone functionality**
   ```bash
   # Create virtual environment
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt

   # Run tests
   pytest tests/

   # Test Docker build
   docker build -t violentutf-api:test .
   docker-compose up -d
   ```

2. **Verify API endpoints**
   - Test all endpoints
   - Verify authentication
   - Check database connectivity
   - Validate external service integrations

## Post-Extraction Setup

### 1. Repository Configuration
- [ ] Set up branch protection rules
- [ ] Configure GitHub Actions workflows
- [ ] Enable security scanning
- [ ] Set up Dependabot
- [ ] Configure issue and PR templates

### 2. Documentation
- [ ] Create comprehensive README.md
- [ ] Document API endpoints
- [ ] Add installation guide
- [ ] Create development guide
- [ ] Document synchronization process

### 3. CI/CD Pipeline
- [ ] Implement automated testing with coverage requirements
- [ ] Set up strict linting and formatting rules
- [ ] Configure comprehensive security scanning
- [ ] Implement automated deployment with approval gates
- [ ] Set up monitoring, alerting, and SLO tracking
- [ ] Add GSA compliance checks
- [ ] Configure dependency vulnerability scanning

### 4. Code Quality Standards
As an official GSA repository, implement elevated standards:

- [ ] Mandatory code review by 2+ reviewers
- [ ] Minimum 80% test coverage requirement
- [ ] Type hints required for all Python code
- [ ] Security scan must pass before merge
- [ ] Documentation required for all endpoints
- [ ] Performance benchmarks for critical paths
- [ ] Accessibility compliance for all outputs

## Synchronization Strategy

### Approach: Selective Sync with Version Tracking

1. **Version Alignment**
   - Tag releases in both repositories
   - Document version compatibility
   - Maintain compatibility matrix

2. **Change Propagation**
   ```bash
   # For bug fixes and critical updates
   # In mother repo
   git format-patch -1 <commit-hash>

   # In API repo
   git apply --3way <patch-file>
   ```

3. **Regular Sync Reviews**
   - Weekly review of changes in both repos
   - Monthly sync meeting between teams
   - Quarterly compatibility assessment

4. **Sync Tooling**
   ```bash
   # Create sync script
   #!/bin/bash
   # sync-from-mother.sh

   # Add mother repo as remote
   git remote add mother https://github.com/GSA-TTS/violentutf.git
   git fetch mother

   # Cherry-pick specific changes
   git cherry-pick <commit-hash>
   ```

### Divergence Management

1. **Expected Divergence**
   - Standalone authentication replacing Keycloak
   - Direct API access replacing APISIX gateway
   - Different technology stack choices
   - GSA-specific compliance features
   - Enhanced security controls
   - Stricter code quality standards

2. **Synchronized Elements**
   - Core business logic (when compatible)
   - Security patches (after GSA review)
   - Critical bug fixes (if applicable)
   - API contract compatibility (where needed)

3. **One-Way Sync Only**
   - Components tied to APISIX/Keycloak
   - Mother repo's relaxed quality standards
   - Non-GSA compliant patterns

## Risk Assessment

### Technical Risks

1. **Divergence Complexity** (Medium)
   - Risk: Repos diverge too much to sync
   - Mitigation: Regular sync reviews, clear boundaries

2. **Duplicate Maintenance** (Medium)
   - Risk: Fixing bugs in two places
   - Mitigation: Automated sync tooling, clear ownership

3. **Integration Breaking** (Low)
   - Risk: Changes break mother repo integration
   - Mitigation: Comprehensive integration tests

### Organizational Risks

1. **Communication Gaps** (Medium)
   - Risk: Teams work in silos
   - Mitigation: Regular sync meetings, shared channels

2. **Ownership Confusion** (Low)
   - Risk: Unclear responsibility boundaries
   - Mitigation: Document ownership clearly

## Timeline

### Week 1: Extraction
- Day 1: Repository preparation
- Day 2: Restructuring
- Day 3: Configuration
- Day 4: Validation
- Day 5: Documentation

### Week 2: Setup
- Day 6-7: CI/CD implementation
- Day 8-9: Testing and optimization
- Day 10: Team training

### Week 3: Stabilization
- Day 11-12: Monitor both repositories
- Day 13-14: Address issues
- Day 15: Project review

## Ongoing Maintenance

### Regular Tasks

1. **Weekly**
   - Review changes in both repositories
   - Identify sync candidates
   - Run integration tests

2. **Monthly**
   - Team sync meeting
   - Update compatibility matrix
   - Review divergence metrics

3. **Quarterly**
   - Assess synchronization strategy
   - Plan major updates
   - Review team feedback

### Success Metrics

1. **Development Velocity**
   - Measure PR turnaround time
   - Track deployment frequency
   - Monitor bug resolution time

2. **Synchronization Health**
   - Number of successful syncs
   - Time to propagate critical fixes
   - Divergence indicators

3. **Team Satisfaction**
   - Developer survey results
   - Onboarding time for new developers
   - Cross-team collaboration frequency

## Conclusion

This extraction strategy enables the ViolentUTF API to become an independent project while maintaining its integration with the mother repository. By carefully managing synchronization and allowing controlled divergence, both projects can evolve to best serve their specific needs while sharing critical updates and fixes.

---

**Document Version**: 2.0
**Last Updated**: 2024-07-24
**Status**: Ready for Implementation
