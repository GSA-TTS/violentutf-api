# Enhanced Reporting Module

This module provides comprehensive, secure, and customizable report generation for architectural audit results, addressing GitHub Issue #44.

## Features

### 🔒 Security-First Design
- **XSS Prevention**: All user data is properly encoded using context-aware encoding
- **Path Traversal Protection**: File paths are validated and sanitized
- **Input Validation**: Comprehensive validation of all input data
- **Sandboxed Templates**: Jinja2 sandboxed environment for HTML generation
- **Security Levels**: Configurable data exposure (PUBLIC, INTERNAL, RESTRICTED, FULL)

### 📊 Multiple Export Formats
- **HTML**: Interactive reports with visualizations using Chart.js
- **PDF**: Professional documents using ReportLab
- **JSON**: Structured data with schema validation

### 🚀 Performance Optimization
- **Parallel Export**: Generate multiple formats simultaneously
- **Streaming Support**: Handle large datasets efficiently
- **Caching**: Integrated with existing cache system

### 📈 Statistical Integration
- **Hotspot Analysis**: Full integration with Issue #43 statistical analysis
- **Temporal Trends**: Visualize code quality trends over time
- **Risk Distribution**: Comprehensive risk assessment visualizations

## Installation

```bash
# Core dependencies (already in requirements.txt)
pip install jinja2 jsonschema

# Optional for PDF generation
pip install reportlab

# Optional for advanced visualizations
pip install matplotlib plotly
```

## Quick Start

### Basic Usage

```python
from tools.pre_audit.reporting import ReportConfig, ExportManager, SecurityLevel

# Configure reporting
report_config = ReportConfig(
    output_dir=Path("reports"),
    security_level=SecurityLevel.INTERNAL,
    enable_charts=True,
    include_hotspots=True,
    export_formats=["html", "json", "pdf"]
)

# Create export manager
export_manager = ExportManager(report_config)

# Generate all reports
output_paths = export_manager.export_all(audit_results)
```

### Integration with claude_code_auditor.py

```python
# Run audit
auditor = EnterpriseClaudeCodeAuditor(config)
audit_results = await auditor.run_comprehensive_audit()

# Generate enhanced reports
report_config = ReportConfig(
    base_config=config,  # Reuse auditor config
    security_level=SecurityLevel.INTERNAL
)

export_manager = ExportManager(report_config)
reports = export_manager.export_all(audit_results)
```

## Configuration Options

### ReportConfig

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `output_dir` | Path | "reports" | Output directory for reports |
| `enable_charts` | bool | True | Include visualizations |
| `include_recommendations` | bool | True | Include remediation guidance |
| `include_executive_summary` | bool | True | Generate executive summary |
| `security_level` | SecurityLevel | INTERNAL | Data exposure level |
| `include_hotspots` | bool | True | Include hotspot analysis |
| `enable_parallel_export` | bool | True | Use parallel processing |
| `export_formats` | List[str] | ["html", "json"] | Formats to generate |

### Security Levels

- **PUBLIC**: Minimal data, redacted paths, no sensitive information
- **INTERNAL**: Standard reports for internal teams
- **RESTRICTED**: Detailed data for security teams
- **FULL**: Complete data for administrators

## Architecture

```
reporting/
├── __init__.py              # Module exports
├── base.py                  # Base classes and interfaces
├── security/                # Security components
│   ├── input_validator.py   # Input validation
│   ├── output_encoder.py    # Output encoding
│   └── hotspot_sanitizer.py # Hotspot data sanitization
├── exporters/               # Report generators
│   ├── html_generator.py    # HTML reports
│   ├── json_generator.py    # JSON reports
│   └── pdf_generator.py     # PDF reports
├── hotspot_integration.py   # Statistical analysis integration
├── export_manager.py        # Parallel export coordination
└── templates/               # Report templates
    └── audit_report.html    # Main HTML template
```

## Security Considerations

### Input Validation
- All file paths are validated against directory traversal
- String inputs are checked for XSS patterns
- JSON data is validated against schemas
- Size limits prevent DoS attacks

### Output Encoding
- Context-aware encoding (HTML, JavaScript, CSS, URL)
- Template auto-escaping with Jinja2
- Safe filename generation
- Proper JSON serialization

### Data Sanitization
- Configurable security levels
- Path redaction for public reports
- Sensitive data removal
- Statistical confidence thresholds

## Examples

### Generate Executive Summary
```python
# Configure for executives
report_config = ReportConfig(
    security_level=SecurityLevel.PUBLIC,
    include_executive_summary=True,
    include_hotspots=False,  # Too technical
    export_formats=["html", "pdf"]
)

# Generate
html_gen = HTMLReportGenerator(report_config)
html_path = html_gen.generate(audit_results)
```

### Security Team Report
```python
# Configure for security team
report_config = ReportConfig(
    security_level=SecurityLevel.RESTRICTED,
    include_hotspots=True,
    statistical_confidence_threshold=0.99,
    export_formats=["json", "pdf"]
)

# Generate with full details
export_manager = ExportManager(report_config)
reports = export_manager.export_all(audit_results)
```

### Create Distribution Archive
```python
# Generate all formats and archive
archive_path = export_manager.export_to_archive(
    audit_results,
    archive_name="audit_reports_2024Q1.zip"
)
```

## Extending the Module

### Custom Report Generator
```python
from tools.pre_audit.reporting.base import ReportGenerator

class CustomReportGenerator(ReportGenerator):
    def generate(self, audit_data: Dict[str, Any]) -> Path:
        # Validate data
        validated = self.validator.validate_audit_data(audit_data)

        # Process data
        report_data = self.data_processor.prepare_report_data(validated)

        # Generate custom format
        output_path = self._get_output_path("custom")
        # ... custom generation logic ...

        return output_path
```

### Custom Templates
Place custom Jinja2 templates in `templates/` directory:

```html
<!-- templates/custom_section.html -->
<section class="custom-section">
    <h2>{{ section_title }}</h2>
    {% for item in items %}
        <div class="item">{{ item | e }}</div>
    {% endfor %}
</section>
```

## Performance Tips

1. **Use Parallel Export**: Enable `enable_parallel_export` for multiple formats
2. **Limit Hotspot Display**: Set `max_hotspots_display` for large codebases
3. **Use Streaming**: For very large datasets, use `JSONReportGenerator.generate_streaming()`
4. **Configure Workers**: Adjust `MAX_WORKERS` in ExportManager for your system

## Troubleshooting

### Common Issues

1. **PDF Generation Fails**
   - Install ReportLab: `pip install reportlab`
   - Check font availability on system

2. **Template Not Found**
   - Ensure templates directory exists
   - Default templates are created automatically

3. **Memory Issues with Large Reports**
   - Use streaming JSON generation
   - Reduce `max_violations_per_page`
   - Process in batches

### Debug Mode
```python
import logging
logging.getLogger('tools.pre_audit.reporting').setLevel(logging.DEBUG)
```

## Testing

Run unit tests:
```bash
pytest tests/unit/pre_audit/test_reporting.py -v
```

Run integration tests:
```bash
pytest tests/integration/test_reporting_integration.py -v
```

## Contributing

When adding new features:
1. Maintain security-first approach
2. Add proper input validation
3. Include unit tests
4. Update documentation
5. Follow existing code patterns

## License

MIT License - See repository LICENSE file
