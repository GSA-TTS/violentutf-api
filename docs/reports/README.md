# Reports

This directory contains various reports generated during the development and extraction of the ViolentUTF API.

## Available Reports

### [Issue #12 Completion Report](./ISSUE_12_COMPLETION_REPORT.md)
- Summary of core framework extraction
- Test results and coverage
- Security scan results
- Completed tasks checklist

### [Issue #12 Verification](./ISSUE_12_VERIFICATION.md)
- Detailed verification of all requirements
- Evidence of completion
- Directory structure documentation
- Implementation details

### [Extraction Summary](./EXTRACTION_SUMMARY.md)
- Overview of extraction process
- Key decisions made
- Architecture changes
- Migration notes

## Report Categories

### Implementation Reports
- Feature completion status
- Technical decisions
- Architecture documentation
- Migration guides

### Quality Reports
- Test coverage analysis
- Code quality metrics
- Performance benchmarks
- Security scan results

### Compliance Reports
- GSA standards compliance
- FISMA requirements
- Accessibility compliance
- Security compliance

## Generating Reports

### Test Coverage Report
```bash
pytest --cov=app --cov-report=html
# Report available in htmlcov/index.html
```

### Security Scan Report
```bash
bandit -r app/ -f json -o bandit-report.json
pip-audit --output-format json > pip-audit-report.json
```

### Performance Report
```bash
locust -f tests/performance/locustfile.py
```

## Historical Reports

Reports are organized by date and issue number for easy reference:
- `ISSUE_<number>_<type>_REPORT.md`
- Example: `ISSUE_12_COMPLETION_REPORT.md`
