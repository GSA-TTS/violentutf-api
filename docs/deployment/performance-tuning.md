# Performance Tuning Guide

## Table of Contents
- [Overview](#overview)
- [Quick Start](#quick-start)
- [Database Performance](#database-performance)
- [Redis Cache Optimization](#redis-cache-optimization)
- [Server Configuration](#server-configuration)
- [Request Handling](#request-handling)
- [Monitoring & Metrics](#monitoring--metrics)
- [Performance Benchmarks](#performance-benchmarks)
- [Optimization Strategies](#optimization-strategies)
- [Troubleshooting](#troubleshooting)

## Overview

This guide covers performance tuning options for the ViolentUTF API. All performance settings can be configured through environment variables, allowing you to optimize for your specific workload without code changes.

The API is built with async/await patterns throughout, providing excellent concurrent request handling. Proper tuning can significantly improve throughput and response times.

## Quick Start

For a typical deployment (4 CPU cores, 8GB RAM):

```env
# Optimal settings for medium load
WORKERS_PER_CORE=2
MAX_WORKERS=8
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=5
REDIS_URL=redis://localhost:6379/0
CACHE_TTL=300
KEEPALIVE=5
MAX_REQUEST_SIZE=10485760  # 10MB
REQUEST_TIMEOUT=60
```

## Database Performance

### Connection Pool Configuration

The application uses SQLAlchemy with async support and connection pooling.

```env
# Number of persistent connections to maintain
DATABASE_POOL_SIZE=5  # Range: 1-20, Default: 5

# Maximum overflow connections during peak load
DATABASE_MAX_OVERFLOW=10  # Range: 0-20, Default: 10
```

#### Pool Sizing Formula

Calculate optimal pool size:
```
POOL_SIZE = (number_of_workers × 2) + overhead
```

Where:
- `number_of_workers` = MAX_WORKERS setting
- `overhead` = 2-4 connections for background tasks

#### Examples:

**Light Load (1-2 workers):**
```env
DATABASE_POOL_SIZE=5
DATABASE_MAX_OVERFLOW=5
```

**Medium Load (4-8 workers):**
```env
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=10
```

**Heavy Load (10+ workers):**
```env
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10
```

### Database URL Configuration

```env
# PostgreSQL (recommended for production)
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/dbname  # pragma: allowlist secret

# SQLite (development only)
DATABASE_URL=sqlite+aiosqlite:///./app.db
```

**Performance tips:**
- Use `asyncpg` driver for PostgreSQL (fastest)
- Enable connection pooling in your database
- Consider read replicas for read-heavy workloads
- Monitor slow queries and add indexes

### Query Optimization

The application includes these optimizations:
- Lazy loading prevention
- Query result caching
- Batch operations support
- Connection retry logic

## Redis Cache Optimization

### Cache Configuration

```env
# Redis connection URL
REDIS_URL=redis://localhost:6379/0

# Default cache TTL in seconds
CACHE_TTL=300  # Range: 60-3600, Default: 300 (5 minutes)
```

### Connection Pool Settings

The Redis client automatically configures:
- Max connections: 20
- Socket keepalive: enabled
- Retry on timeout: enabled
- Decode responses: enabled

### Cache Strategy by Data Type

```env
# Short-lived data (user sessions, rate limits)
CACHE_TTL=300  # 5 minutes

# Medium-lived data (API responses, computed results)
CACHE_TTL=900  # 15 minutes

# Long-lived data (configuration, reference data)
CACHE_TTL=3600  # 1 hour
```

### Memory Optimization

Monitor Redis memory usage:
```bash
redis-cli INFO memory
```

Optimization strategies:
- Use appropriate TTLs
- Implement cache eviction policies
- Monitor key patterns
- Use Redis data types efficiently

## Server Configuration

### Worker Configuration

```env
# Workers per CPU core
WORKERS_PER_CORE=1  # Range: 1-4, Default: 1

# Maximum number of workers
MAX_WORKERS=10  # Range: 1-100, Default: 10

# TCP socket keepalive
KEEPALIVE=5  # Range: 0-300 seconds, Default: 5
```

#### Worker Calculation

Optimal workers = `CPU_CORES × WORKERS_PER_CORE`

**Examples:**

**2 CPU cores:**
```env
WORKERS_PER_CORE=2
MAX_WORKERS=4  # 2 cores × 2 workers
```

**4 CPU cores:**
```env
WORKERS_PER_CORE=2
MAX_WORKERS=8  # 4 cores × 2 workers
```

**8 CPU cores:**
```env
WORKERS_PER_CORE=2
MAX_WORKERS=16  # 8 cores × 2 workers
```

#### Worker Type Considerations

- **CPU-bound workloads**: Use WORKERS_PER_CORE=1
- **I/O-bound workloads**: Use WORKERS_PER_CORE=2-4
- **Mixed workloads**: Use WORKERS_PER_CORE=2

### Server Binding

```env
# Server host and port
SERVER_HOST=0.0.0.0  # For Docker/production
SERVER_PORT=8000     # Default: 8000
```

**Behind a reverse proxy:**
```env
SERVER_HOST=127.0.0.1  # More secure if proxy is on same host
KEEPALIVE=65  # Should be > proxy timeout
```

## Request Handling

### Request Size Limits

```env
# Maximum request size in bytes
MAX_REQUEST_SIZE=10485760  # Default: 10MB (10 * 1024 * 1024)
```

**Common scenarios:**
- JSON APIs: 1-10MB
- File uploads: 50-100MB
- Large data imports: 100MB+

### Request Timeouts

```env
# Request timeout in seconds
REQUEST_TIMEOUT=60  # Range: 10-300, Default: 60
```

**Timeout recommendations:**
- Simple CRUD: 30 seconds
- Complex queries: 60 seconds
- Data processing: 120-300 seconds
- File uploads: Based on size/speed

### Response Compression

GZip compression is enabled by default:
- Minimum size: 1000 bytes
- Compression level: 6 (balanced)
- Automatic for text/JSON responses

## Monitoring & Metrics

### Prometheus Metrics

```env
# Enable Prometheus metrics
ENABLE_METRICS=true  # Default: true

# Metrics endpoint port
METRICS_PORT=9090   # Default: 9090
```

Access metrics at: `http://localhost:9090/metrics`

### Key Metrics to Monitor

**Application metrics:**
- `http_requests_total` - Total requests by endpoint
- `http_request_duration_seconds` - Response time histogram
- `http_requests_in_progress` - Current active requests
- `health_check_duration_seconds` - Health check performance

**System metrics:**
- CPU utilization per worker
- Memory usage
- Database connection pool usage
- Redis connection pool usage

### Performance Targets

Set up alerts for:
- Response time p95 > 200ms
- Error rate > 1%
- CPU usage > 80%
- Memory usage > 90%
- Database pool exhaustion

## Performance Benchmarks

### Small Deployment (2 CPU, 4GB RAM)

```env
WORKERS_PER_CORE=2
MAX_WORKERS=4
DATABASE_POOL_SIZE=5
DATABASE_MAX_OVERFLOW=5
CACHE_TTL=300
```

**Expected performance:**
- Throughput: ~500 requests/second
- Response time p50: <50ms
- Response time p95: <200ms
- Concurrent users: ~100

### Medium Deployment (4 CPU, 8GB RAM)

```env
WORKERS_PER_CORE=2
MAX_WORKERS=8
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=10
CACHE_TTL=300
```

**Expected performance:**
- Throughput: ~1000 requests/second
- Response time p50: <40ms
- Response time p95: <150ms
- Concurrent users: ~250

### Large Deployment (8 CPU, 16GB RAM)

```env
WORKERS_PER_CORE=2
MAX_WORKERS=16
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10
CACHE_TTL=600
```

**Expected performance:**
- Throughput: ~2000 requests/second
- Response time p50: <30ms
- Response time p95: <100ms
- Concurrent users: ~500

## Optimization Strategies

### 1. Caching Strategy

**Enable caching for:**
- Expensive computations
- External API calls
- Database aggregations
- Static configuration

**Cache key patterns:**
```python
# User-specific: f"user:{user_id}:{resource}"
# Global: f"global:{resource}:{version}"
# Time-based: f"stats:{date}:{metric}"
```

### 2. Database Optimization

**Indexes:**
- Add indexes for frequent WHERE clauses
- Use composite indexes for multi-column queries
- Monitor slow query logs

**Query optimization:**
- Use select_related/join for related data
- Limit result sets with pagination
- Use database-level aggregation

### 3. Async Optimization

**Best practices:**
- Use `asyncio.gather()` for parallel operations
- Avoid blocking I/O in async functions
- Use connection pools for all external services
- Implement circuit breakers for external APIs

### 4. Load Balancing

For high availability:
- Deploy multiple instances
- Use a load balancer (nginx, HAProxy)
- Enable session affinity if needed
- Monitor instance health

## Troubleshooting

### High Response Times

**Symptoms:** p95 response time > 500ms

**Check:**
1. Database query performance
2. Cache hit rates
3. Worker CPU usage
4. External API latencies

**Solutions:**
- Increase cache TTL
- Add database indexes
- Scale workers
- Implement circuit breakers

### Database Pool Exhaustion

**Symptoms:** "QueuePool limit exceeded" errors

**Solutions:**
```env
# Increase pool size
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10

# Or reduce worker count
MAX_WORKERS=6
```

### High Memory Usage

**Symptoms:** Memory usage > 90%

**Check:**
- Large response payloads
- Memory leaks in background tasks
- Cache size

**Solutions:**
- Implement pagination
- Stream large responses
- Reduce cache TTL
- Monitor memory per worker

### Redis Connection Issues

**Symptoms:** "Redis connection refused" errors

**Solutions:**
```env
# Check Redis is running
REDIS_URL=redis://localhost:6379/0

# For Docker networking
REDIS_URL=redis://redis:6379/0
```

### Load Testing

Use tools like `locust` or `k6`:

```python
# locustfile.py example
from locust import HttpUser, task, between

class APIUser(HttpUser):
    wait_time = between(1, 3)

    @task
    def health_check(self):
        self.client.get("/api/v1/health")

    @task(3)
    def api_endpoint(self):
        self.client.get("/api/v1/endpoint")
```

Run load test:
```bash
locust -f locustfile.py -H http://localhost:8000 -u 100 -r 10
```

## Performance Monitoring Commands

### Database Connections
```sql
-- PostgreSQL active connections
SELECT count(*) FROM pg_stat_activity;

-- Connection states
SELECT state, count(*)
FROM pg_stat_activity
GROUP BY state;
```

### Redis Monitoring
```bash
# Redis info
redis-cli INFO stats

# Monitor commands in real-time
redis-cli MONITOR
```

### System Resources
```bash
# CPU and memory per process
htop

# Network connections
netstat -an | grep :8000

# Disk I/O
iotop
```

## Related Documentation

- [Deployment Guide](./README.md) - Production deployment
- [Monitoring Setup](./monitoring.md) - Metrics and alerting
- [Database Guide](./database.md) - Database configuration
- [Scaling Guide](./scaling.md) - Horizontal scaling strategies
