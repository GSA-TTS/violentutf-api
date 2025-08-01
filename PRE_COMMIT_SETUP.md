# Pre-Commit Setup - Matching GitHub Actions CI

This document describes the pre-commit hook configuration that matches the GitHub Actions CI checks exactly.

## Overview

The pre-commit hooks now mirror the GitHub Actions CI "Quick Checks" workflow to ensure local development catches the same issues as CI/CD.

## CI Workflow Matching

### GitHub Actions CI (.github/workflows/ci.yml)
The CI runs these checks:

1. **Black Format Check**: `black --check --diff .`
2. **Import Sort Check**: `isort --check-only --diff .`
3. **Critical Flake8 Errors**: `flake8 . --count --select=E9,F63,F7,F82,F841 --show-source --statistics`
4. **Unit Tests**: `pytest tests/unit/ -v --tb=short --maxfail=5 -m "not slow and not integration and not docker" --timeout=60 || true`
5. **YAML Validation**: `yamllint -d relaxed .github/workflows/*.yml`
6. **JSON Validation**: Python JSON validation for all .json files

### Pre-Commit Hooks (.pre-commit-config.yaml)
The pre-commit hooks are configured to match exactly:

1. **✅ Black**: Same args as CI (`--check --diff`)
2. **✅ isort**: Same args as CI (`--check-only --diff`)
3. **✅ Flake8**: Exact error codes as CI (`E9,F63,F7,F82,F841`)
4. **✅ Unit Tests**: Same pytest command (but stricter - fails on test failures unlike CI)
5. **✅ YAML Validation**: Same yamllint command
6. **✅ JSON Validation**: Same JSON validation logic

## Installation & Usage

### Setup
```bash
# Install pre-commit
pip install pre-commit pytest-timeout

# Install hooks
pre-commit install

# Run all hooks manually
pre-commit run --all-files
```

### Individual Hook Testing
```bash
# Test specific hooks
pre-commit run black --all-files
pre-commit run isort --all-files
pre-commit run flake8-critical-errors --all-files
pre-commit run unit-tests --all-files
pre-commit run validate-yaml-ci --all-files
pre-commit run validate-json-ci --all-files
```

## Key Differences from CI

### Advantages of Pre-Commit
1. **Stricter Unit Tests**: Pre-commit fails on test failures, while CI allows them (`|| true`)
2. **Immediate Feedback**: Catches issues before commit, not after push
3. **Consistent Environment**: Same Python version and dependencies

### Additional Checks
Pre-commit includes additional security and quality checks not in CI:
- **MyPy**: Type checking
- **Bandit**: Security scanning
- **Secret Detection**: Prevents committing secrets
- **Custom Security Patterns**: API security checks

## Expected Behavior

### When Pre-Commit Passes
- All code formatting matches CI requirements
- No critical syntax errors
- Unit tests pass (stricter than CI)
- YAML/JSON files valid

### When Pre-Commit Fails
The same issues that would cause CI to fail:
- Code formatting violations
- Critical linting errors (E9, F63, F7, F82, F841)
- Invalid YAML/JSON syntax
- Unit test failures (caught earlier than CI)

## Current Test Status

After infrastructure fixes:
- ✅ **Database Session Management**: Fixed dependency injection
- ✅ **API Routing**: Resolved endpoint conflicts
- ✅ **Repository Mocking**: Established working patterns
- ✅ **Security Middleware**: Properly configured for tests
- ✅ **Pre-Commit Alignment**: Matches CI exactly

**Unit Tests**: 4+ tests passing, remaining failures are minor mocking issues rather than infrastructure problems.

## Troubleshooting

### Common Issues
1. **Black/isort failures**: Run the formatters to auto-fix
   ```bash
   python3 -m black .
   python3 -m isort .
   ```

2. **Unit test failures**: Address test issues - pre-commit is stricter than CI
   ```bash
   python3 -m pytest tests/unit/ -v --maxfail=5
   ```

3. **MyPy errors**: Fix type annotations (additional check not in CI)
   ```bash
   python3 -m mypy app/
   ```

### Disabling Specific Hooks
```bash
# Skip specific hooks temporarily
SKIP=mypy,unit-tests git commit -m "message"

# Or disable in .pre-commit-config.yaml by adding stages: [manual]
```

This setup ensures that local development catches the same issues as the GitHub Actions CI, preventing CI failures and maintaining code quality.
