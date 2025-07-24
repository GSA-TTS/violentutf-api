#!/bin/bash
# Run tests with coverage

set -e  # Exit on error

echo "Running ViolentUTF API Tests..."
echo "================================"

# Install test dependencies if needed
pip install -q -r requirements-dev.txt

# Run tests with coverage
echo "Running unit tests..."
pytest tests/unit -v --cov=app --cov-report=term-missing --cov-report=html

echo ""
echo "Running integration tests..."
pytest tests/integration -v

echo ""
echo "Running all tests with coverage report..."
pytest -v --cov=app --cov-report=term-missing --cov-report=html --cov-report=xml

echo ""
echo "Coverage report generated in htmlcov/index.html"
echo "================================"
