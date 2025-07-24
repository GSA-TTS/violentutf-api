# ViolentUTF API Synchronization Strategy

## Overview

This document outlines the strategy for maintaining synchronization between the ViolentUTF mother repository and the standalone ViolentUTF API repository. The goal is to enable independent development while ensuring critical updates, bug fixes, and security patches can be shared between repositories.

**Important**: The ViolentUTF API operates as a completely standalone service without dependencies on APISIX, Keycloak, or other ViolentUTF components. As an official GSA repository, it maintains higher code quality standards and may adopt technologies not present in the mother repository. Synchronization must respect these architectural and quality differences.

## Synchronization Principles

### 1. Selective Synchronization
- Not all changes need to be synchronized
- Focus on bug fixes, security patches, and critical features
- Allow repositories to diverge for repository-specific optimizations

### 2. Directional Flow
- **Primary Flow**: Mother repo → API repo (for shared components)
- **Secondary Flow**: API repo → Mother repo (for API-specific fixes)
- **Bidirectional**: Security patches and critical bug fixes

### 3. Version Compatibility
- Maintain compatibility matrix between repositories
- Tag synchronized versions for tracking
- Document breaking changes

## Synchronization Categories

### Always Sync
1. **Security Patches**
   - Authentication/authorization fixes
   - Vulnerability patches
   - Security dependency updates

2. **Critical Bug Fixes**
   - Data corruption fixes
   - Performance regression fixes
   - API breaking bug fixes

3. **Core Business Logic**
   - Shared algorithms
   - Data validation rules
   - Core model updates

### Selectively Sync
1. **Feature Enhancements**
   - Evaluate benefit vs. complexity
   - Consider repository-specific needs
   - Maintain backward compatibility

2. **Performance Optimizations**
   - Repository-specific optimizations may differ
   - Sync only if beneficial to both

3. **Documentation Updates**
   - API documentation stays separate
   - Sync architectural decisions

### Never Sync
1. **Repository-Specific Configuration**
   - CI/CD pipelines (GSA-specific in API repo)
   - Deployment configurations
   - Environment-specific settings
   - GSA compliance configurations

2. **Architecture-Specific Code**
   - APISIX gateway integrations
   - Keycloak authentication code
   - Any code below GSA quality standards
   - Components tied to ViolentUTF stack

3. **Test Infrastructure**
   - Different testing requirements
   - Repository-specific test data
   - Integration tests with external components

4. **Quality Compromises**
   - Code without proper type hints
   - Code with <80% test coverage
   - Undocumented functionality
   - Non-compliant security patterns

## Technical Implementation

### 1. Git Remote Setup
```bash
# In API repository
git remote add upstream https://github.com/GSA-TTS/violentutf.git
git remote -v

# In mother repository (if syncing back)
git remote add api-repo https://github.com/GSA-TTS/violentutf-api.git
```

### 2. Sync Scripts

#### sync-from-mother.sh
```bash
#!/bin/bash
set -e

# Configuration
UPSTREAM_REMOTE="upstream"
API_PATH="violentutf_api"
SYNC_BRANCH="sync/mother-$(date +%Y%m%d-%H%M%S)"

# Fetch latest
echo "Fetching latest from mother repository..."
git fetch $UPSTREAM_REMOTE

# Create sync branch
git checkout -b $SYNC_BRANCH

# Get commits from specific path
echo "Analyzing commits to sync..."
git log --oneline $UPSTREAM_REMOTE/main -- $API_PATH -10

# Interactive selection
echo "Enter commit hash to sync (or 'exit' to cancel):"
read COMMIT_HASH

if [ "$COMMIT_HASH" != "exit" ]; then
    # Create patch
    git format-patch -1 $COMMIT_HASH -- $API_PATH

    # Apply with path transformation
    git apply --3way *.patch -p2 --directory=app

    # Clean up
    rm *.patch

    echo "Sync complete. Review changes and create PR."
fi
```

#### sync-to-mother.sh
```bash
#!/bin/bash
set -e

# Configuration
API_REMOTE="origin"
MOTHER_PATH="../violentutf"
SYNC_BRANCH="sync/api-$(date +%Y%m%d-%H%M%S)"

# Get commit to sync
echo "Enter commit hash from API repo to sync:"
read COMMIT_HASH

# Create patch
git format-patch -1 $COMMIT_HASH

# In mother repo
cd $MOTHER_PATH
git checkout -b $SYNC_BRANCH

# Apply patch with path adjustment
git apply --3way ../violentutf-api/*.patch \
  --directory=violentutf_api/fastapi_app

echo "Patch applied to mother repo. Review and create PR."
```

### 3. Automated Sync Checks

#### GitHub Action for Sync Monitoring
```yaml
name: Sync Check

on:
  schedule:
    - cron: '0 9 * * 1'  # Weekly on Mondays
  workflow_dispatch:

jobs:
  check-sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Add upstream
        run: |
          git remote add upstream https://github.com/GSA-TTS/violentutf.git
          git fetch upstream

      - name: Check for sync candidates
        run: |
          echo "## Sync Candidates Report" > sync-report.md
          echo "Generated: $(date)" >> sync-report.md
          echo "" >> sync-report.md

          echo "### Recent Mother Repo Changes" >> sync-report.md
          git log --oneline upstream/main -- violentutf_api/ -20 >> sync-report.md

          echo "" >> sync-report.md
          echo "### Divergence Metrics" >> sync-report.md
          echo "Unique commits in API repo: $(git rev-list --count origin/main ^upstream/main)" >> sync-report.md
          echo "API changes in mother repo: $(git rev-list --count upstream/main -- violentutf_api/)" >> sync-report.md

      - name: Create issue if needed
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('sync-report.md', 'utf8');

            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: 'Weekly Sync Review',
              body: report,
              labels: ['sync', 'maintenance']
            });
```

## Quality Gates for Synchronization

Before any code from the mother repository can be synchronized to the ViolentUTF API repository, it must pass the following quality gates:

### 1. Code Quality Requirements
- [ ] All functions have type hints
- [ ] Test coverage ≥ 80% for affected code
- [ ] No security vulnerabilities detected
- [ ] Passes strict linting rules
- [ ] All endpoints documented

### 2. Architectural Compatibility
- [ ] No APISIX dependencies
- [ ] No Keycloak dependencies
- [ ] Works with standalone authentication
- [ ] Compatible with direct API access

### 3. GSA Compliance
- [ ] Meets accessibility standards
- [ ] Follows secure coding practices
- [ ] Includes proper audit logging
- [ ] Has required documentation

### 4. Review Process
- [ ] Code review by 2+ reviewers
- [ ] Security review if applicable
- [ ] Performance impact assessed
- [ ] Breaking changes documented

## Sync Workflow Process

### 1. Weekly Review Process
1. **Monday**: Automated sync check runs
2. **Tuesday**: Team reviews sync candidates
3. **Wednesday**: Create sync PRs if needed
4. **Thursday**: Test and review sync PRs
5. **Friday**: Merge approved syncs

### 2. Emergency Sync Process
For critical security patches:
1. Immediate notification to both teams
2. Create emergency sync PR
3. Expedited review process
4. Deploy to both repositories

### 3. Conflict Resolution
1. **Automated Resolution**: Use `--3way` merge
2. **Manual Resolution**: For complex conflicts
3. **Team Discussion**: For architectural conflicts
4. **Defer**: If conflict is too complex

## Tracking and Metrics

### 1. Sync Log
Maintain a synchronization log in both repositories:

```markdown
# Synchronization Log

## 2024-07-24
- **Type**: Security Patch
- **Direction**: Mother → API
- **Commit**: abc123
- **Description**: Fixed authentication bypass
- **Status**: Completed

## 2024-07-20
- **Type**: Bug Fix
- **Direction**: API → Mother
- **Commit**: def456
- **Description**: Fixed rate limiting issue
- **Status**: Completed
```

### 2. Compatibility Matrix

| Mother Repo Version | API Repo Version | Compatibility | Notes |
|-------------------|------------------|---------------|-------|
| v2.5.0 | v1.0.0 | Full | Initial extraction |
| v2.6.0 | v1.1.0 | Full | Synced security patches |
| v2.7.0 | v1.2.0 | Partial | API diverged on auth |
| v3.0.0 | v2.0.0 | Breaking | Major refactor |

### 3. Success Metrics
- **Sync Success Rate**: % of syncs without conflicts
- **Time to Sync**: Average time from identification to merge
- **Divergence Index**: Number of unique commits per repo
- **Compatibility Score**: % of shared tests passing

## Best Practices

### 1. Commit Hygiene
- Keep commits atomic and focused
- Use clear commit messages
- Reference sync tracking in commits

### 2. Documentation
- Document why a sync was skipped
- Explain complex conflict resolutions
- Update compatibility matrix regularly

### 3. Communication
- Announce major syncs in team channels
- Discuss architectural changes before syncing
- Share lessons learned from sync issues

### 4. Testing
- Run full test suite after each sync
- Test integration between repositories
- Maintain sync-specific test scenarios

## Tools and Automation

### 1. Sync Dashboard
Create a simple dashboard to track:
- Pending syncs
- Sync history
- Divergence metrics
- Compatibility status

### 2. Sync Bot
Consider implementing a bot that:
- Monitors both repositories
- Suggests sync candidates
- Creates sync PRs automatically
- Tracks sync metrics

### 3. Pre-commit Hooks
```bash
#!/bin/bash
# .git/hooks/pre-commit

# Check for sync markers
if git diff --cached --name-only | grep -q "SYNC_REQUIRED"; then
    echo "Found SYNC_REQUIRED marker. Please document sync plan."
    exit 1
fi
```

## Appendix

### A. Sync Decision Tree
```
Is it a security fix? → YES → Always sync
                     ↓ NO
Is it a critical bug? → YES → Always sync
                     ↓ NO
Is it core business logic? → YES → Usually sync
                          ↓ NO
Is it repo-specific? → YES → Don't sync
                    ↓ NO
Evaluate case-by-case
```

### B. Common Sync Patterns

1. **Security Patch Pattern**
```bash
# Fast-track security patches
git cherry-pick --strategy=recursive -X theirs <commit>
```

2. **Feature Sync Pattern**
```bash
# Careful feature sync with testing
git checkout -b sync/feature-x
git cherry-pick <commit>
# Run full test suite
# Create PR for review
```

3. **Bulk Sync Pattern**
```bash
# For multiple related commits
git format-patch <start>..<end> -- path/
git am *.patch
```

---

**Document Version**: 1.0
**Last Updated**: 2024-07-24
**Review Schedule**: Quarterly
