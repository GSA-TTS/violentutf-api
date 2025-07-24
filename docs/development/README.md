# Development Guide

## Getting Started

### Prerequisites

- Python 3.11+
- Git
- Virtual environment tool (venv, virtualenv, or conda)
- PostgreSQL (optional, SQLite used by default)
- Redis (optional, for caching)

### Initial Setup

1. Clone the repository:
```bash
git clone https://github.com/GSA-TTS/violentutf-api.git
cd violentutf-api
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

4. Set up pre-commit hooks:
```bash
pre-commit install
```

5. Copy environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

6. Run the application:
```bash
python -m app.main
# Or use uvicorn directly:
uvicorn app.main:app --reload
```

## Development Workflow

### 1. Create Feature Branch
```bash
git checkout develop
git pull origin develop
git checkout -b feature/your-feature-name
```

### 2. Make Changes
- Write code following the style guide
- Add tests for new functionality
- Update documentation as needed

### 3. Run Tests
```bash
# Run all tests
make test

# Run specific test file
pytest tests/unit/test_security.py

# Run with coverage
make test-coverage
```

### 4. Code Quality Checks
```bash
# Run all quality checks
make quality

# Individual checks
make format      # Black & isort
make lint        # Flake8
make type-check  # Mypy
make security    # Bandit
```

### 5. Commit Changes
```bash
# Pre-commit hooks will run automatically
git add .
git commit -m "feat: add new feature"
```

### 6. Push and Create PR
```bash
git push origin feature/your-feature-name
# Create PR on GitHub
```

## Code Style Guide

### Python Style
- Follow PEP 8
- Use Black for formatting (line length: 88)
- Use isort for import sorting
- Type hints required for all functions

### Naming Conventions
- Classes: PascalCase
- Functions/variables: snake_case
- Constants: UPPER_SNAKE_CASE
- Private methods: _leading_underscore

### Project Structure
```python
# Good
from app.core.security import hash_password
from app.models.user import User

# Bad
from core.security import hash_password
from models import *
```

## Testing Guidelines

### Test Structure
```python
class TestFeatureName:
    """Test suite for FeatureName."""

    def test_should_do_something_when_condition(self):
        """Test that feature does something under specific condition."""
        # Arrange
        expected = "result"

        # Act
        result = function_under_test()

        # Assert
        assert result == expected
```

### Test Coverage
- Minimum 80% coverage required
- Focus on business logic
- Test edge cases and error conditions

## Common Tasks

### Add New Endpoint
1. Create endpoint in `app/api/endpoints/`
2. Add route to `app/api/routes.py`
3. Write tests in `tests/unit/` and `tests/integration/`
4. Update API documentation

### Add New Middleware
1. Create middleware in `app/middleware/`
2. Register in `app/main.py`
3. Add tests
4. Document in architecture docs

### Update Dependencies
```bash
# Update specific package
pip install --upgrade package-name
pip freeze > requirements.txt

# Security check
pip-audit
```

## Debugging

### Enable Debug Mode
Set in `.env`:
```
DEBUG=true
LOG_LEVEL=DEBUG
```

### Common Issues

1. **Import Errors**: Ensure running from project root
2. **Database Errors**: Check DATABASE_URL in .env
3. **Type Errors**: Run `mypy app/` to check
4. **Test Failures**: Check test fixtures and mocks

## Useful Commands

```bash
# Development server with auto-reload
make dev

# Run specific test with output
pytest -vvs tests/unit/test_security.py::TestPasswordHashing::test_hash_password

# Check what would be changed by black
black --check --diff .

# Generate test coverage HTML report
pytest --cov=app --cov-report=html
# Open htmlcov/index.html
```

## Environment Variables

Key environment variables for development:

```bash
# Application
ENVIRONMENT=development
DEBUG=true
SECRET_KEY=your-secret-key-min-32-chars

# Server
SERVER_HOST=127.0.0.1
SERVER_PORT=8000

# Database
DATABASE_URL=sqlite:///./violentutf.db

# Logging
LOG_LEVEL=DEBUG
LOG_FORMAT=text

# Features
RATE_LIMIT_ENABLED=false
ENABLE_METRICS=false
```

## IDE Setup

### VS Code
Recommended extensions:
- Python
- Pylance
- Black Formatter
- isort
- Python Test Explorer

Settings (`.vscode/settings.json`):
```json
{
    "python.linting.enabled": true,
    "python.linting.flake8Enabled": true,
    "python.formatting.provider": "black",
    "python.sortImports.args": ["--profile", "black"],
    "editor.formatOnSave": true,
    "python.testing.pytestEnabled": true
}
```

### PyCharm
- Set interpreter to virtual environment
- Enable Black as formatter
- Configure pytest as test runner
