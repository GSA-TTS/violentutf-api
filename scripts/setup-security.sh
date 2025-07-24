#!/bin/bash
# Setup security and code quality tools for violentutf-api

echo "🔒 Setting up security and code quality tools..."

# Install pre-commit and security tools
echo "📦 Installing security tools..."
pip install --upgrade pip
pip install pre-commit detect-secrets
pip install bandit safety pip-audit

# Verify tool versions
echo "🔍 Verifying tool versions..."
echo "pre-commit: $(pre-commit --version)"
echo "bandit: $(bandit --version 2>&1 | head -1)"
echo "safety: $(safety --version)"
echo "pip-audit: $(pip-audit --version)"

# Install pre-commit hooks
echo "🪝 Installing pre-commit hooks..."
pre-commit install
pre-commit install --hook-type commit-msg

# Generate secrets baseline
echo "🔍 Generating secrets baseline..."
detect-secrets scan > .secrets.baseline

# Run initial pre-commit on all files
echo "🏃 Running initial pre-commit checks..."
pre-commit run --all-files || true

# Create security directory
mkdir -p security

# Create security scan script
cat > scripts/security-scan.sh << 'EOF'
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
safety check --json --output security/safety-report.json || true

# pip-audit (Google/PyPA maintained, free)
echo "→ Running pip-audit..."
pip-audit --format json --output security/pip-audit-report.json

# Detect secrets (Yelp maintained)
echo "→ Checking for secrets..."
detect-secrets scan --baseline .secrets.baseline

echo "✅ Security scans complete! Check security/ directory for reports."
EOF

chmod +x scripts/security-scan.sh

echo "✅ Security setup complete!"
echo ""
echo "📝 Next steps:"
echo "1. Review and commit .secrets.baseline"
echo "2. Configure GitHub repository security settings"
echo "3. Add custom secret patterns in GitHub settings"
echo "4. Run 'pre-commit run --all-files' to check existing code"
echo "5. Run './scripts/security-scan.sh' for security audit"
echo "6. Commit all security configuration files"
