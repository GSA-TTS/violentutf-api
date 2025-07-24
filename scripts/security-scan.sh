#!/bin/bash
# Run all security scans

echo "🔍 Running security scans..."

# Create security reports directory
mkdir -p security

# Bandit (PyCQA maintained)
echo "→ Running Bandit..."
bandit -r . -f json -o security/bandit-report.json \
  -x '/tests/,/app_data/,/violentutf_logs/' \
  --skip B101,B601

# Safety (paid tool with free tier)
echo "→ Running Safety..."
safety check --save-json security/safety-report.json || true

# pip-audit (Google/PyPA maintained, free)
echo "→ Running pip-audit..."
pip-audit --format json --output security/pip-audit-report.json

# Detect secrets (Yelp maintained)
echo "→ Checking for secrets..."
detect-secrets scan --baseline .secrets.baseline

echo "✅ Security scans complete! Check security/ directory for reports."
