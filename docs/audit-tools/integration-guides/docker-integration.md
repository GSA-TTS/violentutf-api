# Docker Integration Guide

This guide covers Docker-based deployment and execution of the database audit tools.

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- Basic familiarity with containerization

## Installation

### Docker Setup

**Build audit tools image**:

```bash
# Build the audit tools Docker image
docker build -t violentutf-audit-tools .

# Build using docker-compose
docker-compose build audit-tools
```

**Run audit container**:

```bash
# Run basic audit
docker run --rm -v $(pwd):/workspace violentutf-audit-tools

# Run with environment variables
docker run --rm \
  -e DATABASE_URL="postgresql://user:pass@host:5432/db" \
  -e REDIS_URL="redis://host:6379" \
  -v $(pwd)/audit-reports:/app/reports \
  violentutf-audit-tools
```

## Configuration

### Docker Compose Configuration

**docker-compose.audit.yml**:

```yaml
version: '3.8'
services:
  audit-tools:
    build: .
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - AUDIT_OUTPUT_DIR=/app/reports
    volumes:
      - ./audit-reports:/app/reports
      - ./audit-baselines:/app/baselines
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: audit_db
      POSTGRES_USER: audit_user
      POSTGRES_PASSWORD: audit_pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

## Usage

### Basic Docker Execution

```bash
# Run full audit with docker-compose
docker-compose -f docker-compose.audit.yml up audit-tools

# Run specific audit tool
docker-compose -f docker-compose.audit.yml exec audit-tools \
  python3 tools/inventory/data_asset_inventory.py
```

### Advanced Docker Usage

```python
# Python script for Docker integration
import docker

client = docker.from_env()

# Run audit in container
container = client.containers.run(
    "violentutf-audit-tools",
    environment={
        "DATABASE_URL": "postgresql://user:pass@db:5432/audit"
    },
    volumes={
        "/host/audit-reports": {"bind": "/app/reports", "mode": "rw"}
    },
    remove=True
)
```

## Examples

**Production Deployment Example**:

```bash
# Deploy audit tools in production
docker-compose -f docker-compose.prod.yml up -d

# Scale audit workers
docker-compose -f docker-compose.prod.yml scale audit-worker=3
```

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `image` | `str` | Docker image name and tag |
| `environment` | `dict` | Environment variables |
| `volumes` | `dict` | Volume mount configurations |

## Returns

Docker execution returns:
- `container_id`: Container identifier
- `exit_code`: Container exit code
- `logs`: Container execution logs

## Installation Requirements

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
CMD ["python3", "tools/inventory/data_asset_inventory.py"]
```
