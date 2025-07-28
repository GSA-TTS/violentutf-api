# Security Policy

As a U.S. Government agency, the General Services Administration (GSA) takes
seriously our responsibility to protect the public's information, including
financial and personal information, from unwarranted disclosure.

## Reporting a Vulnerability

Services operated by the U.S. General Services Administration (GSA)
are covered by the **GSA Vulnerability Disclosure Program (VDP)**.

See the [GSA Vulnerability Disclosure Policy](https://gsa.gov/vulnerability-disclosure-policy)
at <https://www.gsa.gov/vulnerability-disclosure-policy> for details including:

* How to submit a report if you believe you have discovered a vulnerability.
* GSA's coordinated disclosure policy.
* Information on how you may conduct security research on GSA developed
  software and systems.
* Important legal and policy guidance.

### [Bug Bounties](https://hackerone.com/gsa_bbp)

Certain GSA/TTS programs have bug bounties that are not discussed at the above link. If you find security issues for any of the following domains:

* 18f.gov
* cloud.gov
* fedramp.gov
* login.gov
* search.gov
* usa.gov
* vote.gov

you should also review the [GSA Bug Bounty program](https://hackerone.com/gsa_bbp) at <https://hackerone.com/gsa_bbp/> for a potential bounty.

## Supported Versions

Please note that only certain branches are supported with security updates.

| Version (Branch) | Supported          |
| ---------------- | ------------------ |
| main             | :white_check_mark: |
| other            | :x:                |

When using this code or reporting vulnerabilities please only use supported
versions.

## Security Tools and Configurations

This repository implements multiple layers of security controls to ensure code quality and prevent security vulnerabilities.

### Automated Security Scanning

#### Pre-commit Hooks
We use pre-commit hooks to catch security issues before they enter the codebase. Install with:
```bash
pip install pre-commit
pre-commit install
```

Security-focused hooks include:
- **Bandit**: Scans Python code for common security issues
- **detect-secrets**: Prevents secrets from being committed
- **Custom hooks**: Check for hardcoded credentials, insecure patterns
- **Additional checks**: File hygiene, private key detection, API security patterns

#### Continuous Security Monitoring

1. **Dependabot**: Automated dependency updates
   - Monitors Python, Docker, and GitHub Actions dependencies
   - Creates PRs for security updates weekly
   - Groups related updates for easier review

2. **GitHub Security Features** (must be enabled in repository settings):
   - Secret scanning with push protection
   - Code scanning with CodeQL
   - Dependency vulnerability alerts

3. **Scheduled Security Scans**: Weekly comprehensive security analysis
   - CodeQL advanced queries
   - Trivy container scanning
   - OWASP dependency checking

### Running Security Scans Locally

#### Initial Setup
```bash
# Run the security setup script
./scripts/setup-security.sh
```

This script will:
- Install all security tools (bandit, safety, pip-audit, detect-secrets)
- Configure pre-commit hooks
- Generate an initial secrets baseline
- Create security scanning scripts

#### Manual Security Audit
```bash
# Run comprehensive security scans
./scripts/security-scan.sh
```

This generates reports in the `security/` directory:
- `bandit-report.json`: Python security issues
- `safety-report.json`: Known vulnerabilities in dependencies
- `pip-audit-report.json`: Supply chain security audit

**Note**: The safety command syntax is: `safety check --save-json security/safety-report.json`

#### Pre-commit Security Checks
```bash
# Run all pre-commit hooks on all files
pre-commit run --all-files

# Update the secrets baseline after reviewing
detect-secrets scan --baseline .secrets.baseline
```

### Security Configuration Files

1. **`.github/dependabot.yml`**: Automated dependency management
2. **`.pre-commit-config.yaml`**: Pre-commit security hooks (configured for Python 3.12)
3. **`.gitleaks.toml`**: Custom secret detection patterns
4. **`.allstar/`**: GitHub security policy enforcement (with solo developer overrides)
5. **`.secrets.baseline`**: Baseline for detect-secrets (review before committing)

### Custom Secret Patterns

The following patterns are configured for detection:
- ViolentUTF API keys: `VUTF_API_[A-Z0-9]{32}`
- JWT secrets: `jwt_secret_[a-zA-Z0-9]{64}`
- Database URLs with embedded credentials
- Private keys (RSA, EC, SSH, etc.)

### Security Best Practices

1. **Never commit secrets**: Use environment variables or secret management services
2. **Review security alerts**: Address Dependabot and security scan findings promptly
3. **Sign your commits**: Use GPG signing for commit authenticity (`git config commit.gpgsign true`)
4. **Use least privilege**: Follow principle of least privilege for API keys and access
5. **Regular audits**: Run `./scripts/security-scan.sh` before releases
6. **False positives**: Review `.secrets.baseline` for false positives (e.g., example patterns in docs)
7. **Python version**: Ensure pre-commit uses your system Python version (currently configured for 3.12)

### Security Contacts

For security issues specific to this repository:
- Create a security advisory in GitHub
- Or follow the GSA Vulnerability Disclosure Policy above

For questions about security configurations:
- Review the security setup documentation
- Check the pre-commit and scanning tool logs
