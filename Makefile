hooksPath := $(git config --get core.hooksPath)

.PHONY: precommit help install install-dev test test-unit test-integration test-coverage format lint type-check security-scan run dev clean

default: help

precommit:
ifneq ($(strip $(hooksPath)),.github/hooks)
	@git config --add core.hooksPath .github/hooks
endif
	pre-commit run --all-files

help:
	@echo "ViolentUTF API - Available commands:"
	@echo "  make install        Install dependencies"
	@echo "  make install-dev    Install development dependencies"
	@echo "  make test          Run all tests"
	@echo "  make test-unit     Run unit tests only"
	@echo "  make test-integration Run integration tests only"
	@echo "  make test-coverage Run tests with coverage report"
	@echo "  make format        Format code with Black and isort"
	@echo "  make lint          Run linting checks"
	@echo "  make type-check    Run type checking with mypy"
	@echo "  make security-scan Run security scans"
	@echo "  make run           Run the API server"
	@echo "  make dev           Run the API server in development mode"
	@echo "  make clean         Clean up generated files"
	@echo "  make precommit     Run pre-commit hooks"

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt
	pre-commit install

test:
	pytest tests/ -v

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

test-coverage:
	pytest --cov=app --cov-report=html --cov-report=term-missing --cov-fail-under=80

format:
	black app/ tests/ --line-length=120
	isort app/ tests/ --profile=black --line-length=120

lint:
	flake8 app/ tests/ --max-line-length=120

type-check:
	mypy app/ --ignore-missing-imports --no-strict-optional

security-scan:
	bandit -r app/ -ll
	pip-audit
	@echo "Checking for secrets..."
	@detect-secrets scan --baseline .secrets.baseline

run:
	uvicorn app.main:app --host 0.0.0.0 --port 8000

dev:
	uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .coverage htmlcov/ .pytest_cache/ .mypy_cache/
	rm -rf test.db
