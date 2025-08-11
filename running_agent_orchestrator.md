# Running Agent Orchestrator Tools in ViolentUTF-API

This guide explains how to use the agent_orchestrator tools that have been added as a submodule under `tools/agent_orchestrator/` in the violentutf-api repository.

## Prerequisites

1. **Ensure submodule is initialized:**
   ```bash
   git submodule update --init --recursive
   ```

2. **Install required dependencies:**
   ```bash
   # Core dependencies
   pip install claude-code-sdk pyyaml click jinja2

   # For implement_Eissue.py tool
   pip install pytest behave pytestarch
   ```

3. **Claude Code SDK Requirements:**
   - You need a Claude Pro or Max subscription
   - No API key required if using Claude Pro/Max

## Available Tools

### 1. FailCheck Tool - Automated Pre-commit Fixer
Automatically fixes pre-commit check failures using Claude Code SDK.

**From violentutf-api root:**
```bash
# Basic usage - fix pre-commit failures
python tools/agent_orchestrator/failcheck.py --repo-path .

# With verbose output (level 1 - summary)
python tools/agent_orchestrator/failcheck.py --repo-path . -v

# With detailed output (level 2 - full)
python tools/agent_orchestrator/failcheck.py --repo-path . -vv

# Set maximum fix iterations (default: 3)
python tools/agent_orchestrator/failcheck.py --repo-path . --max-iterations 5
```

**Features:**
- 🔄 Iteratively fixes failures until all checks pass
- 🤖 AI-powered fixes using Claude Code SDK
- 📊 Multiple verbose levels for debugging
- 🛡️ Safe operation with rollback capabilities

### 2. Write ADR Tool - Architecture Decision Record Generator
Analyzes GitHub Enhancement Issues and generates comprehensive ADRs.

**From violentutf-api root:**
```bash
# Generate ADR from GitHub issue
python tools/agent_orchestrator/write_adr.py --repo-path . --issue 123

# Custom ADR directory path
python tools/agent_orchestrator/write_adr.py --repo-path . --issue 456 --adr-path docs/ADRs

# With verbose output
python tools/agent_orchestrator/write_adr.py --repo-path . --issue 789 -v

# With detailed output
python tools/agent_orchestrator/write_adr.py --repo-path . --issue 789 -vv
```

**Features:**
- 🔍 Extracts Architecturally Significant Requirements (ASRs)
- 📊 Identifies high-impact architectural decisions
- 📝 Generates ADRs following best practices
- 🤖 Two-phase process: Analysis → ADR Generation

**Output:**
- Analysis report: `docs/reports/ISSUE_{number}_AnalysisADR.md`
- Generated ADR: `docs/architecture/ADRs/ADR-{number}-{title}.md`

### 3. Implement Enhancement Issue Tool - Automated Implementation
Transforms GitHub Enhancement Issues into production-ready code with tests.

**From violentutf-api root:**
```bash
# Full implementation (all phases)
python tools/agent_orchestrator/implement_Eissue.py --repo-path . --issue 123

# Run specific phase only
python tools/agent_orchestrator/implement_Eissue.py --repo-path . --issue 123 --phase analyze
python tools/agent_orchestrator/implement_Eissue.py --repo-path . --issue 123 --phase blueprint
python tools/agent_orchestrator/implement_Eissue.py --repo-path . --issue 123 --phase implement

# Custom paths
python tools/agent_orchestrator/implement_Eissue.py --repo-path . --issue 456 \
    --adr-path docs/ADRs --planning-path docs/planning

# With verbose output
python tools/agent_orchestrator/implement_Eissue.py --repo-path . --issue 789 -v
```

**Three-Phase Process:**
1. **ASR Analysis**: Extracts requirements and maps to ADRs
2. **Blueprint Creation**: Creates user stories and technical tasks
3. **Implementation**: Generates code with TDD/BDD and architectural compliance

**Features:**
- 🔍 Analyzes issues for Architecturally Significant Requirements
- 📋 Maps requirements to existing ADRs
- 📝 Creates detailed implementation blueprints
- 🧪 Implements Test-Driven Development with pytest
- 🏗️ Behavior-Driven Development with behave
- 🎯 Architectural compliance with pytestarch
- 🛡️ STRIDE threat modeling and OWASP principles
- 📊 Requirements traceability matrix

**Output:**
- ASR Analysis: `docs/planning/ISSUE_{number}/ISSUE_{number}_ASRs.md`
- Blueprint: `docs/planning/ISSUE_{number}/ISSUE_{number}_plan.md`
- Implementation: Source code, tests, and BDD features

### 4. Setup Repo Tool - Repository Structure Generator
Creates professional CI/CD and repository structure.

**From violentutf-api root (to set up a new project):**
```bash
# Interactive mode - choose from templates
python tools/agent_orchestrator/setup_repo_cli.py

# Setup Python API repository
python tools/agent_orchestrator/setup_repo_cli.py --type python-api

# Setup Python Library
python tools/agent_orchestrator/setup_repo_cli.py --type python-library

# With custom configuration file
python tools/agent_orchestrator/setup_repo_cli.py --config my-config.yml

# Specify target directory
python tools/agent_orchestrator/setup_repo_cli.py --repo-path ./new-project --type python-api
```

**Features:**
- 📁 Comprehensive project structure (docs/, tests/, tools/)
- 🔄 GitHub Actions workflows (CI/CD, security scanning)
- 🧹 Pre-commit configuration with quality checks
- 📚 Auto-generated documentation (README, CONTRIBUTING, SECURITY)
- 🔧 Tool-specific configurations (pytest, mypy, black, etc.)

## Convenience Setup

### Create Shell Aliases

Add these aliases to your `~/.zshrc` for easier access:

```bash
# Agent Orchestrator aliases for violentutf-api
alias vutf-failcheck='python tools/agent_orchestrator/failcheck.py --repo-path .'
alias vutf-adr='python tools/agent_orchestrator/write_adr.py --repo-path .'
alias vutf-implement='python tools/agent_orchestrator/implement_Eissue.py --repo-path .'
alias vutf-setup='python tools/agent_orchestrator/setup_repo_cli.py'

# With common options
alias vutf-failcheck-v='python tools/agent_orchestrator/failcheck.py --repo-path . -v'
alias vutf-adr-v='python tools/agent_orchestrator/write_adr.py --repo-path . -v'
alias vutf-implement-analyze='python tools/agent_orchestrator/implement_Eissue.py --repo-path . --phase analyze'
```

After adding aliases, reload your shell:
```bash
source ~/.zshrc
```

### Usage with Aliases

```bash
# Fix pre-commit failures
vutf-failcheck
vutf-failcheck-v  # with verbose output

# Generate ADR for issue #123
vutf-adr --issue 123

# Implement issue #456
vutf-implement --issue 456

# Just analyze issue #789
vutf-implement-analyze --issue 789
```

## Working from Agent Orchestrator Directory

Alternatively, you can work directly from the tools directory:

```bash
# Navigate to agent_orchestrator
cd tools/agent_orchestrator

# Run tools without --repo-path flag
python failcheck.py
python write_adr.py --issue 123
python implement_Eissue.py --issue 456
python setup_repo_cli.py --type python-api

# Return to violentutf-api root
cd ../..
```

## Common Use Cases

### 1. Fix All Pre-commit Failures
```bash
python tools/agent_orchestrator/failcheck.py --repo-path . -v
```

### 2. Document an Architectural Decision
```bash
# First analyze the issue
python tools/agent_orchestrator/write_adr.py --repo-path . --issue 150 -v

# Review generated files:
# - docs/reports/ISSUE_150_AnalysisADR.md
# - docs/architecture/ADRs/ADR-XXX-*.md
```

### 3. Implement a New Feature
```bash
# Full automated implementation
python tools/agent_orchestrator/implement_Eissue.py --repo-path . --issue 200

# Or step by step:
# 1. Analyze requirements
python tools/agent_orchestrator/implement_Eissue.py --repo-path . --issue 200 --phase analyze

# 2. Review and create blueprint
python tools/agent_orchestrator/implement_Eissue.py --repo-path . --issue 200 --phase blueprint

# 3. Generate implementation
python tools/agent_orchestrator/implement_Eissue.py --repo-path . --issue 200 --phase implement
```

### 4. Set Up a New Microservice
```bash
# Create new service directory
mkdir services/new-service
cd services/new-service

# Run setup tool
python ../../tools/agent_orchestrator/setup_repo_cli.py --type python-api

# Return to root
cd ../..
```

## Troubleshooting

### Import Errors
```bash
# Install all dependencies
pip install -r tools/agent_orchestrator/requirements.txt

# Or install manually
pip install claude-code-sdk pyyaml click jinja2 pytest behave pytestarch
```

### GitHub CLI Not Authenticated
```bash
gh auth login
```

### Claude Code SDK Issues
- Ensure you have Claude Pro or Max subscription
- No API key needed for Pro/Max users
- Check internet connection

### Permission Errors
```bash
# Make scripts executable
chmod +x tools/agent_orchestrator/*.py
```

### Path Issues
Always use `--repo-path .` when running from violentutf-api root, or navigate to the target directory first.

## Security Notes

The tools have restricted permissions:
- ✅ Can read, edit, write files
- ✅ Can run safe bash commands (ls, grep, etc.)
- ✅ Can access GitHub CLI
- ❌ Cannot delete files (rm disabled)
- ❌ Cannot modify git history (git checkout disabled)
- ❌ Cannot access database URLs

## Support

For issues or questions:
- Check tool-specific README files in `tools/agent_orchestrator/`
- Use verbose mode (-v or -vv) for debugging
- Review generated logs and outputs
- Consult the main agent_orchestrator repository documentation

---

**Note**: These tools use AI assistance to accelerate development but should not replace human review, especially for security-critical and performance-sensitive code.
