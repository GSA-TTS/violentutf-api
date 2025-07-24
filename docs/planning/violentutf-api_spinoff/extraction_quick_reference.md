# ViolentUTF API Extraction Quick Reference

## Overview
This guide provides quick commands for extracting the ViolentUTF API into a standalone repository while keeping both repositories active and synchronized.

**Key Points:**
- The API runs standalone without APISIX, Keycloak, or other ViolentUTF components
- As an official GSA repository, it maintains higher code quality standards
- The API may adopt new technologies not present in the mother repository

## Key Commands

### 1. Prepare Workspace
```bash
# Create workspace for extraction
mkdir -p ~/violentutf-extraction
cd ~/violentutf-extraction

# Clone mother repository (keep as reference)
git clone https://github.com/GSA-TTS/violentutf.git violentutf-reference
```

### 2. Extract with History
```bash
# Clone for extraction
git clone https://github.com/GSA-TTS/violentutf.git violentutf-api-extract
cd violentutf-api-extract

# Install git-filter-repo if needed
pip install git-filter-repo

# Extract API code with history
git filter-repo \
  --path violentutf_api/ \
  --path tests/api_tests/ \
  --path tests/test_orchestrator_api.py \
  --path tests/test_unit_api_endpoints.py \
  --path tests/test_apisix_integration.py \
  --path .github/workflows/*api*.yml \
  --path docker-compose.api.yml
```

### 3. Restructure Repository
```bash
# Flatten directory structure
mv violentutf_api/fastapi_app/* .
mv violentutf_api/migrations ./migrations
mv violentutf_api/docker-compose.yml ./docker-compose.yml 2>/dev/null || true

# Organize tests
mkdir -p tests/integration
mv tests/api_tests/* tests/ 2>/dev/null || true
mv tests/test_*api*.py tests/integration/ 2>/dev/null || true

# Clean up
rm -rf violentutf_api
find . -type d -empty -delete
```

### 4. Remove External Dependencies
```bash
# Find APISIX references to remove
grep -r "apisix" . --include="*.py" --include="*.yml"

# Find Keycloak references to remove
grep -r "keycloak" . --include="*.py" --include="*.yml"

# Remove gateway-specific code
find . -name "*gateway*" -o -name "*apisix*" -o -name "*keycloak*"

# Update authentication to standalone
# This will require manual code changes to implement built-in auth
```

### 5. Update Import Paths
```bash
# Update Python imports
find . -name "*.py" -type f -exec sed -i '' \
  -e 's/from violentutf_api\.fastapi_app/from app/g' \
  -e 's/import violentutf_api\.fastapi_app/import app/g' \
  -e 's/violentutf_api\.fastapi_app\./app./g' \
  {} +

# Fix any remaining violentutf references
find . -name "*.py" -type f -exec sed -i '' \
  -e 's/from violentutf\./from /g' \
  {} +
```

### 6. Set Up New Repository
```bash
# Remove old origin
git remote remove origin

# Add new origin
git remote add origin https://github.com/GSA-TTS/violentutf-api.git

# Add mother repo as upstream for syncing
git remote add upstream https://github.com/GSA-TTS/violentutf.git

# Push to new repository
git branch -M main
git push -u origin main
```

### 7. Configure for Standalone Operation
```bash
# Copy configuration files to root
cp app/requirements*.txt . 2>/dev/null || true
cp app/Dockerfile* . 2>/dev/null || true
cp app/.env.template .env.example 2>/dev/null || true

# Update Docker paths
sed -i '' 's|./violentutf_api/fastapi_app|.|g' docker-compose.yml
sed -i '' 's|WORKDIR /app/violentutf_api/fastapi_app|WORKDIR /app|g' Dockerfile
```

## Synchronization Commands

### Set Up Sync Tools
```bash
# Create sync directory
mkdir -p .sync
cd .sync

# Create sync script
cat > sync-from-mother.sh << 'EOF'
#!/bin/bash
# Sync specific changes from mother repo

COMMIT_HASH=$1
if [ -z "$COMMIT_HASH" ]; then
    echo "Usage: $0 <commit-hash>"
    exit 1
fi

# Fetch latest from mother repo
git fetch upstream

# Create patch
git format-patch -1 $COMMIT_HASH --stdout > $COMMIT_HASH.patch

# Apply patch
git apply --3way $COMMIT_HASH.patch

echo "Patch applied. Review changes and commit if satisfied."
EOF

chmod +x sync-from-mother.sh
```

### Cherry-Pick from Mother Repo
```bash
# Fetch latest changes
git fetch upstream

# View commits in mother repo
git log upstream/main --oneline -10

# Cherry-pick specific commit
git cherry-pick <commit-hash>

# Or create and apply patch
git format-patch -1 upstream/main~5
git apply --3way *.patch
```

### Track Divergence
```bash
# Compare with mother repo
git diff upstream/main:violentutf_api/fastapi_app HEAD:app

# List unique commits in standalone repo
git log --oneline --no-merges origin/main ^upstream/main

# List unique commits in mother repo API
git log --oneline --no-merges upstream/main ^origin/main -- violentutf_api/
```

## Testing Commands

### Verify Standalone Operation
```bash
# Test Python imports
python -m py_compile $(find . -name "*.py")

# Run tests
python -m pytest tests/ -v

# Test Docker build
docker build -t violentutf-api:test .

# Test with docker-compose
docker-compose up -d
docker-compose ps
docker-compose logs -f api
```

### Cross-Repository Testing
```bash
# In mother repo - test API still works
cd ~/violentutf-reference/violentutf
docker-compose -f docker-compose.yml up violentutf-api

# In standalone repo - test independence
cd ~/violentutf-extraction/violentutf-api
docker-compose up -d
```

## Common Path Updates

### Python Files
```python
# Old
from violentutf_api.fastapi_app.app.core import security
# New
from app.core import security

# Old
sys.path.append("violentutf_api/fastapi_app")
# New
sys.path.append(".")
```

### Docker Files
```dockerfile
# Old
COPY violentutf_api/fastapi_app/requirements.txt .
WORKDIR /app/violentutf_api/fastapi_app

# New
COPY requirements.txt .
WORKDIR /app
```

### Docker Compose
```yaml
# Old
build:
  context: ./violentutf_api/fastapi_app
volumes:
  - ./violentutf_api/fastapi_app:/app

# New
build:
  context: .
volumes:
  - .:/app
```

## Maintenance Commands

### Weekly Sync Review
```bash
# Check for updates in mother repo
git fetch upstream
git log --oneline upstream/main -- violentutf_api/ -10

# Generate sync report
echo "=== Sync Report $(date) ===" > sync-report.txt
echo "Mother repo commits:" >> sync-report.txt
git log --oneline upstream/main -- violentutf_api/ -10 >> sync-report.txt
echo -e "\nStandalone repo commits:" >> sync-report.txt
git log --oneline origin/main -10 >> sync-report.txt
```

### Version Tagging
```bash
# Tag compatible versions
MOTHER_VERSION=$(cd ../violentutf-reference && git describe --tags)
git tag -a "v1.0.0-compatible-with-$MOTHER_VERSION" -m "Compatible with mother repo $MOTHER_VERSION"
git push origin --tags
```

## Troubleshooting

### Import Errors
```bash
# Find problematic imports
grep -r "from violentutf" . --include="*.py"
grep -r "import violentutf" . --include="*.py"
```

### Path Issues
```bash
# Find absolute paths
grep -r "/violentutf_api" . --include="*.py" --include="*.yml" --include="*.yaml"
```

### Sync Conflicts
```bash
# When patch fails
git apply --3way sync.patch --reject
# Fix .rej files manually
find . -name "*.rej"
```

## GSA Compliance Setup

### Code Quality Enforcement
```bash
# Set up pre-commit for quality gates
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black
  - repo: https://github.com/PyCQA/isort
    rev: 5.12.0
    hooks:
      - id: isort
  - repo: https://github.com/PyCQA/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        args: ['--max-line-length=120']
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.3.0
    hooks:
      - id: mypy
        args: ['--strict']
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ['-ll']
EOF

pre-commit install
```

### Test Coverage Requirement
```bash
# Add coverage configuration
cat > .coveragerc << 'EOF'
[run]
source = app
omit =
    */tests/*
    */migrations/*

[report]
precision = 2
fail_under = 80
EOF

# Run tests with coverage
pytest --cov=app --cov-report=html --cov-fail-under=80
```

## Quick Health Check
```bash
#!/bin/bash
echo "=== API Extraction Health Check ==="
echo "1. Python syntax check..."
python -m py_compile $(find . -name "*.py") 2>&1 | grep -c "^" | xargs -I {} echo "   {} syntax errors found"

echo "2. Import check..."
grep -r "violentutf_api\." . --include="*.py" | grep -c "^" | xargs -I {} echo "   {} old imports found"

echo "3. External dependency check..."
echo "   APISIX refs: $(grep -r "apisix" . --include="*.py" | grep -c "^")"
echo "   Keycloak refs: $(grep -r "keycloak" . --include="*.py" | grep -c "^")"

echo "4. Type hint check..."
mypy app --strict 2>&1 | tail -1

echo "5. Test coverage..."
pytest --cov=app --cov-report=term-missing:skip-covered | grep TOTAL

echo "6. Docker check..."
docker build -t test:latest . > /dev/null 2>&1 && echo "   ✓ Docker builds successfully" || echo "   ✗ Docker build failed"

echo "7. Standalone operation..."
docker run -d -p 8000:8000 test:latest && echo "   ✓ API runs standalone" || echo "   ✗ Standalone operation failed"

echo "8. Sync status..."
git fetch upstream 2>/dev/null && echo "   ✓ Upstream connection active" || echo "   ✗ No upstream configured"
```

---

**Quick Reference Version**: 2.0
**Purpose**: Rapid extraction and setup of standalone ViolentUTF API repository with synchronization support
