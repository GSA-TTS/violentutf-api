# Database Audit Tools Setup and Installation Guide

This guide provides comprehensive instructions for setting up and installing the database audit automation tools in the ViolentUTF API system.

## Prerequisites

Before installing the database audit tools, ensure your system meets the following requirements:

### System Requirements

- **Python**: 3.9 or higher
- **Operating System**: Linux, macOS, or Windows
- **Memory**: Minimum 4GB RAM (8GB recommended for large projects)
- **Storage**: At least 2GB free disk space for audit reports and baselines
- **Network**: Internet connectivity for dependency installation

### Database Requirements

- **PostgreSQL**: 15+ (for database auditing)
- **Redis**: 7+ (for caching and session management)
- **SQLite**: 3.35+ (for development and testing)

### Optional Dependencies

- **Docker**: For containerized execution
- **Git**: For configuration management integration
- **Node.js**: For web-based report viewing

## Installation

### Method 1: Standard Installation

1. **Clone the Repository**

```bash
git clone https://github.com/GSA-TTS/violentutf-api.git
cd violentutf-api
```

2. **Create Virtual Environment** (Recommended)

```bash
# Create virtual environment
python3 -m venv audit-tools-env

# Activate virtual environment
source audit-tools-env/bin/activate  # On Linux/macOS
# or
audit-tools-env\Scripts\activate  # On Windows
```

3. **Install Dependencies**

```bash
# Install core dependencies
pip install -r requirements.txt

# Install audit-specific dependencies
pip install -r requirements-audit.txt
```

4. **Verify Installation**

```bash
# Test basic functionality
python3 -c "from tools.inventory.data_asset_inventory import DataAssetInventoryTool; print('Installation successful')"
```

### Method 2: Docker Installation

1. **Build Docker Image**

```bash
# Build the audit tools image
docker build -t violentutf-audit-tools .

# Or use docker-compose
docker-compose build audit-tools
```

2. **Run Container**

```bash
# Run basic audit container
docker run --rm -v $(pwd):/workspace violentutf-audit-tools

# Run with docker-compose
docker-compose up audit-tools
```

### Method 3: Development Installation

For development and customization:

```bash
# Clone repository
git clone https://github.com/GSA-TTS/violentutf-api.git
cd violentutf-api

# Install in development mode
pip install -e .

# Install development dependencies
pip install -r requirements-dev.txt

# Run pre-commit hooks setup
pre-commit install
```

## Configuration

### Environment Variables

Create a `.env` file in the project root with the following variables:

```bash
# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/database_name
REDIS_URL=redis://localhost:6379/0

# Audit Configuration
AUDIT_LOG_LEVEL=INFO
AUDIT_OUTPUT_DIR=./audit-reports
AUDIT_BASELINE_DIR=./audit-baselines

# Security (Optional)
ENCRYPTION_KEY=your-encryption-key-here
AUDIT_SECRET_KEY=your-secret-key-here

# Notification Settings (Optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
EMAIL_SMTP_SERVER=smtp.example.com
EMAIL_SMTP_PORT=587
ADMIN_EMAIL=admin@example.com
```

### Database Setup

1. **PostgreSQL Setup**

```bash
# Create audit database
createdb audit_database

# Run initial migrations (if using Alembic)
alembic upgrade head

# Create audit user with appropriate permissions
psql -c "CREATE USER audit_user WITH PASSWORD 'secure_password';"
psql -c "GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO audit_user;"
```

2. **Redis Setup**

```bash
# Start Redis server
redis-server

# Test Redis connection
redis-cli ping
```

### Configuration Files

Create the main audit configuration file:

**audit-config.yaml**
```yaml
database:
  primary:
    url: "${DATABASE_URL}"
    pool_size: 10
    max_overflow: 20
    pool_timeout: 30

  redis:
    url: "${REDIS_URL}"
    db: 0

audit:
  inventory:
    include_schemas: ["public", "audit"]
    exclude_tables: ["temp_*", "cache_*", "session_*"]
    classify_sensitive_data: true

  backup:
    enabled: true
    schedule: "0 2 * * *"  # Daily at 2 AM
    retention_days: 30

  reporting:
    formats: ["json", "yaml", "html"]
    destination: "${AUDIT_OUTPUT_DIR}"
    auto_cleanup: true

logging:
  level: "${AUDIT_LOG_LEVEL}"
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  handlers:
    - console
    - file
```

## Directory Structure

After installation, your project should have the following structure:

```
violentutf-api/
├── tools/
│   ├── inventory/
│   │   ├── data_asset_inventory.py
│   │   ├── repository_analyzer.py
│   │   ├── schema_discovery.py
│   │   └── security_classification.py
│   └── dependency/
│       ├── comprehensive_analyzer.py
│       └── repository_analyzer.py
├── scripts/
│   ├── backup_coverage_audit.py
│   ├── config_baseline_manager.py
│   ├── config_drift_detector.py
│   ├── postgres_backup.py
│   └── redis_backup.py
├── docs/
│   └── audit-tools/
│       ├── api-reference/
│       ├── integration-guides/
│       ├── troubleshooting/
│       └── examples/
├── tests/
│   └── documentation/
├── audit-reports/          # Created during setup
├── audit-baselines/        # Created during setup
└── logs/                   # Created during setup
```

## Verification and Testing

### Basic Functionality Test

Run the following tests to verify installation:

```bash
# Test data asset inventory
python3 tools/inventory/data_asset_inventory.py --test

# Test schema discovery
python3 tools/inventory/schema_discovery.py --test

# Test backup functionality
python3 scripts/postgres_backup.py --test

# Run comprehensive test suite
python3 -m pytest tests/documentation/ -v
```

### Configuration Validation

```bash
# Validate configuration files
python3 -c "
import yaml
with open('audit-config.yaml', 'r') as f:
    config = yaml.safe_load(f)
    print('Configuration file is valid')
"

# Test database connection
python3 -c "
import os
from sqlalchemy import create_engine
engine = create_engine(os.getenv('DATABASE_URL'))
with engine.connect() as conn:
    result = conn.execute('SELECT 1')
    print('Database connection successful')
"

# Test Redis connection
python3 -c "
import os
import redis
r = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
r.ping()
print('Redis connection successful')
"
```

## Troubleshooting Common Installation Issues

### Issue 1: Python Dependencies

**Problem**: `ModuleNotFoundError` during import

**Solution**:
```bash
# Ensure virtual environment is activated
source audit-tools-env/bin/activate

# Reinstall requirements
pip install --upgrade -r requirements.txt

# Check Python path
python3 -c "import sys; print(sys.path)"
```

### Issue 2: Database Connection

**Problem**: `DatabaseConnectionError`

**Solution**:
```bash
# Verify DATABASE_URL format
echo $DATABASE_URL

# Test database connectivity
pg_isready -h localhost -p 5432

# Check database permissions
psql $DATABASE_URL -c "SELECT current_user, session_user;"
```

### Issue 3: Permission Errors

**Problem**: Permission denied errors when writing reports

**Solution**:
```bash
# Create necessary directories with proper permissions
mkdir -p audit-reports audit-baselines logs
chmod 755 audit-reports audit-baselines logs

# Check current user permissions
ls -la audit-reports/
```

### Issue 4: Docker Issues

**Problem**: Docker container fails to start

**Solution**:
```bash
# Check Docker daemon status
docker version

# Rebuild image with no cache
docker build --no-cache -t violentutf-audit-tools .

# Check container logs
docker logs violentutf-audit-tools
```

## Performance Optimization

### Recommended System Settings

```bash
# Increase file descriptor limits (Linux/macOS)
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize Python garbage collection
export PYTHONOPTIMIZE=1

# Configure PostgreSQL connection pooling
# Add to postgresql.conf:
# max_connections = 200
# shared_buffers = 256MB
```

### Database Performance Tuning

**PostgreSQL Optimization**:
```sql
-- Add indexes for audit queries
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);

-- Configure connection pooling
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
```

**Redis Optimization**:
```bash
# Configure Redis memory settings
redis-cli CONFIG SET maxmemory 256mb
redis-cli CONFIG SET maxmemory-policy allkeys-lru
```

## Security Considerations

### File Permissions

```bash
# Set secure permissions on configuration files
chmod 600 .env audit-config.yaml
chmod 700 audit-baselines/
chmod 755 audit-reports/
```

### Database Security

```sql
-- Create dedicated audit user with minimal permissions
CREATE USER audit_readonly WITH PASSWORD 'secure_random_password';
GRANT CONNECT ON DATABASE your_database TO audit_readonly;
GRANT USAGE ON SCHEMA public TO audit_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO audit_readonly;
```

### Secret Management

```bash
# Use environment variables for secrets
export DATABASE_PASSWORD=$(cat /run/secrets/db_password)
export REDIS_PASSWORD=$(cat /run/secrets/redis_password)

# Or use a secrets management service
# export DATABASE_URL=$(vault kv get -field=url secret/database)
```

## Next Steps

After successful installation:

1. **Read the Configuration Guide**: [Configuration Guide](configuration-guide.md)
2. **Learn Execution Workflows**: [Execution Workflows](execution-workflows.md)
3. **Try Docker Integration**: [Docker Integration](docker-integration.md)
4. **Review API Documentation**: [API Reference](../api-reference/inventory-tools.md)
5. **Explore Examples**: [Complete Audit Scenario](../examples/complete-audit-scenario.md)

## Support

If you encounter issues during installation:

1. Check the [Troubleshooting Guide](../troubleshooting/common-issues.md)
2. Review system requirements and dependencies
3. Verify environment variable configuration
4. Test database and Redis connectivity
5. Check file permissions and directory structure

For additional support, consult the project documentation or contact the development team.
