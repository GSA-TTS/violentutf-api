# Development Guide

## Getting Started

### Prerequisites

- Docker 20.10.0+
- Docker Compose 2.0+
- Git
- Python 3.11+ (for local development)
- Make (optional, for convenience commands)

### Quick Setup with Docker (Recommended)

The easiest way to get started is using the automated setup script:

```bash
# Clone the repository
git clone https://github.com/GSA-TTS/violentutf-api.git
cd violentutf-api

# Run automated setup
./setup_violentutf.sh
```

This will:
- Check all prerequisites
- Create necessary configuration files
- Build Docker images
- Start all services (API, PostgreSQL, Redis, Nginx)
- Run database migrations
- Generate admin credentials and API keys
- Display a complete setup summary with credentials

📚 **See the [Setup Guide](../../SETUP_GUIDE.md) for detailed setup instructions and all available options.**

After setup, you can:
- Access the API at http://localhost:8000
- View API documentation at http://localhost:8000/docs
- Check health status at http://localhost:8000/api/v1/health

### Manual Setup (Alternative)

If you prefer to set up the environment manually:

1. Clone the repository:
```bash
git clone https://github.com/GSA-TTS/violentutf-api.git
cd violentutf-api
```

2. Copy environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Build and start services:
```bash
docker compose up -d --build
```

4. Check service status:
```bash
docker compose ps
```

### Local Development Setup (Without Docker)

For local development without Docker:

1. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

3. Set up pre-commit hooks:
```bash
pre-commit install
```

4. Run the application:
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

## Setup Script Management

The `setup_violentutf.sh` script provides various management commands. See the [Setup Guide](../../SETUP_GUIDE.md) for complete documentation.

```bash
# Check prerequisites only
./setup_violentutf.sh --precheck

# Full setup (default)
./setup_violentutf.sh

# View service status
./setup_violentutf.sh --status

# View logs
./setup_violentutf.sh --logs

# Stop services
./setup_violentutf.sh --stop

# Start services
./setup_violentutf.sh --start

# Restart services
./setup_violentutf.sh --restart

# Create backup
./setup_violentutf.sh --backup

# Clean up project resources (preserves data)
./setup_violentutf.sh --cleanup

# Deep cleanup (removes everything including data)
./setup_violentutf.sh --deepcleanup

# Show help
./setup_violentutf.sh --help
```

### View Saved Credentials

After setup, you can view credentials and service information:

```bash
# Display saved credentials
./show_credentials.sh
```

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
