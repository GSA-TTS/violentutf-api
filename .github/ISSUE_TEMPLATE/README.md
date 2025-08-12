# ViolentUTF API Issue Templates

This directory contains UAT (Unified Agentic Task) compliant issue templates for the ViolentUTF API project. These templates are designed to be both human-readable and machine-parsable, enabling AI agents to process and act on issues automatically.

## Available Templates

### Core Development Templates
1. **🎯 Epic** (`01-epic.yml`) - Large-scale initiatives spanning multiple sprints
2. **📖 User Story** (`02-story.yml`) - User-facing features with acceptance criteria
3. **✅ Task** (`03-task.yml`) - Technical implementation tasks
4. **🐛 Bug Report** (`04-bug.yml`) - Defect reports with debugging information

### Specialized Templates
5. **🔒 Security Issue** (`05-security.yml`) - Security vulnerabilities and fixes
6. **⚡ Performance Issue** (`06-performance.yml`) - Performance problems and optimizations
7. **📚 Documentation** (`07-documentation.yml`) - Documentation creation and updates
8. **🔧 Refactor** (`08-refactor.yml`) - Code improvement without functional changes
9. **🧹 Chore** (`09-chore.yml`) - Maintenance tasks and housekeeping
10. **🔬 Research/Spike** (`10-research.yml`) - Technical investigations and evaluations

## UAT Schema

All templates include a YAML frontmatter section that follows the UAT v1.0 schema:

```yaml
---
schemaVersion: "uat-v1.0"
issueID: ""  # Automatically populated
type: ""     # epic, story, task, bug, security, etc.
status: "pending-acceptance"
priority: 1-5
assignee: ""

spec:
  # Type-specific specifications

quality:
  # Quality gates and requirements

relations:
  # Issue relationships and dependencies
---
```

## Usage

### For Humans
1. Click "New Issue" in the GitHub interface
2. Select the appropriate template
3. Fill in all required fields
4. The UAT specification block is pre-configured - modify values but maintain structure

### For AI Agents
Agents can parse issues using the structured YAML frontmatter:

```python
import yaml
import re

def parse_issue(issue_body):
    # Extract YAML frontmatter
    pattern = r'```yaml\n---\n(.*?)\n---\n```'
    match = re.search(pattern, issue_body, re.DOTALL)
    if match:
        return yaml.safe_load(match.group(1))
    return None
```

## Template Categories

### Planning & Design
- **Epic**: Strategic initiatives with measurable business goals
- **Story**: User-centric features with Gherkin acceptance criteria
- **Research**: Time-boxed investigations with clear deliverables

### Implementation
- **Task**: Developer-focused work items with implementation steps
- **Refactor**: Code quality improvements maintaining functionality
- **Documentation**: Technical writing and documentation updates

### Maintenance & Operations
- **Bug**: Defect tracking with reproduction steps
- **Security**: Vulnerability management with CVSS scoring
- **Performance**: Optimization opportunities with metrics
- **Chore**: Routine maintenance and dependency updates

## ViolentUTF API Specific Fields

All templates include fields specific to the security testing platform:

- **Attack Frameworks**: PyRIT, Garak integration points
- **Target Systems**: LLM providers, API endpoints
- **Security Considerations**: STRIDE threat modeling, OWASP categories
- **Compliance**: FedRAMP, security control mappings

## Best Practices

1. **Use the Right Template**: Each template is optimized for its use case
2. **Complete UAT Fields**: Agent automation depends on structured data
3. **Link Related Issues**: Use the relations section to track dependencies
4. **Add Labels**: Templates auto-add base labels, add more as needed
5. **Security First**: Use Security Advisory for critical vulnerabilities

## Automation Support

These templates enable:
- Automatic issue triage and assignment
- AI-powered implementation suggestions
- Dependency tracking and management
- Progress reporting and metrics
- Integration with CI/CD pipelines

## Contributing

When modifying templates:
1. Maintain UAT schema compatibility
2. Test YAML validity
3. Update this README
4. Consider backward compatibility
5. Document changes in CHANGELOG

## Related Documentation

- [UAT Schema Documentation](/docs/architecture/Agent-Consumable GitHub Issues.md)
- [GitHub Issue Templates Guide](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests)
- [ViolentUTF API Contributing Guide](/CONTRIBUTING.md)
