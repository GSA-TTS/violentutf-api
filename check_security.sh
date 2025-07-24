#!/bin/bash
# Quick security check script

echo "Running Security Checks..."
echo "========================="

# Check if dependencies are installed
echo "Checking Python version..."
python --version

echo ""
echo "Running Bandit security scan..."
if command -v bandit &> /dev/null; then
    bandit -r app/ -ll -f json -o bandit_report.json
    echo "Bandit scan complete. Report saved to bandit_report.json"
    # Show summary
    bandit -r app/ -ll
else
    echo "Bandit not installed. Install with: pip install bandit"
fi

echo ""
echo "Checking for known vulnerabilities in dependencies..."
if command -v pip-audit &> /dev/null; then
    pip-audit --desc
else
    echo "pip-audit not installed. Install with: pip install pip-audit"
fi

echo ""
echo "Basic code quality check..."
if command -v flake8 &> /dev/null; then
    flake8 app/ --max-line-length=120 --count --statistics
else
    echo "Flake8 not installed. Install with: pip install flake8"
fi

echo ""
echo "Type checking..."
if command -v mypy &> /dev/null; then
    mypy app/ --ignore-missing-imports --no-strict-optional || true
else
    echo "MyPy not installed. Install with: pip install mypy"
fi

echo ""
echo "========================="
echo "Security check complete!"
