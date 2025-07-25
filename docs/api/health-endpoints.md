# Health Check Endpoints

## Overview

The ViolentUTF API provides comprehensive health check endpoints for monitoring and orchestration.

## Endpoints

### GET /api/v1/health

Basic health check endpoint that returns 200 if the service is running.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-24T10:30:00Z",
  "service": "ViolentUTF API",
  "version": "1.0.0",
  "environment": "development"
}
```

### GET /api/v1/ready

Comprehensive readiness check that validates all dependencies.

**Response (All Healthy):**
```json
{
  "status": "ready",
  "timestamp": "2024-01-24T10:30:00Z",
  "checks": {
    "database": true,
    "cache": true,
    "disk_space": true,
    "memory": true
  },
  "details": {
    "failed_checks": [],
    "service": "ViolentUTF API",
    "version": "1.0.0"
  }
}
```

**Response (Not Ready):**
- Status Code: 503
```json
{
  "status": "not ready",
  "timestamp": "2024-01-24T10:30:00Z",
  "checks": {
    "database": false,
    "cache": true,
    "disk_space": true,
    "memory": true
  },
  "details": {
    "failed_checks": ["database"],
    "service": "ViolentUTF API",
    "version": "1.0.0"
  }
}
```

### GET /api/v1/live

Kubernetes-style liveness probe endpoint.

**Response:**
```json
{
  "status": "alive",
  "timestamp": "2024-01-24T10:30:00Z"
}
```

## Health Check Details

### Database Check
- Verifies database connectivity
- Timeout: 5 seconds
- Optional if DATABASE_URL not configured

### Cache Check
- Validates Redis connectivity
- Timeout: 2 seconds
- Optional if REDIS_URL not configured

### Disk Space Check
- Monitors available disk space
- Threshold: 90% usage
- Checks root partition

### Memory Check
- Monitors system memory usage
- Threshold: 90% usage
- Uses psutil for accurate metrics

## Usage in Orchestration

### Kubernetes Example
```yaml
livenessProbe:
  httpGet:
    path: /api/v1/live
    port: 8000
  initialDelaySeconds: 10
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /api/v1/ready
    port: 8000
  initialDelaySeconds: 5
  periodSeconds: 5
```

### Docker Compose Example
```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```
