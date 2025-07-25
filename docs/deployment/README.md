# Deployment Guide

## Overview

This guide covers deployment options for the ViolentUTF API service.

## Deployment Options

### 1. Docker Deployment

#### Build Image
```bash
docker build -t violentutf-api:latest .
```

#### Run Container
```bash
docker run -d \
  --name violentutf-api \
  -p 8000:8000 \
  -e DATABASE_URL=postgresql://user:pass@db:5432/violentutf \  # pragma: allowlist secret
  -e SECRET_KEY=your-production-secret-key \
  -e ENVIRONMENT=production \
  violentutf-api:latest
```

#### Docker Compose
```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/violentutf  # pragma: allowlist secret
      - REDIS_URL=redis://redis:6379/0
      - SECRET_KEY=${SECRET_KEY}
      - ENVIRONMENT=production
    depends_on:
      - db
      - redis
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass  # pragma: allowlist secret
      - POSTGRES_DB=violentutf
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

### 2. Kubernetes Deployment

See [kubernetes/](./kubernetes/) directory for full manifests.

#### Key Components:
- Deployment with health checks
- Service for load balancing
- ConfigMap for configuration
- Secret for sensitive data
- HorizontalPodAutoscaler for scaling
- NetworkPolicy for security

### 3. Cloud Platform Deployment

#### AWS ECS
- Use Fargate for serverless containers
- Application Load Balancer for routing
- RDS for PostgreSQL
- ElastiCache for Redis
- Secrets Manager for secrets

#### Google Cloud Run
- Fully managed serverless
- Cloud SQL for PostgreSQL
- Cloud Memorystore for Redis
- Secret Manager for secrets

#### Azure Container Instances
- Container groups for multi-container
- Azure Database for PostgreSQL
- Azure Cache for Redis
- Key Vault for secrets

## Production Configuration

### Environment Variables

Required for production:
```bash
# Application
ENVIRONMENT=production
DEBUG=false
SECRET_KEY=<strong-random-key>

# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8000

# Database
DATABASE_URL=postgresql://user:password@host:5432/dbname  # pragma: allowlist secret
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=40

# Redis
REDIS_URL=redis://host:6379/0
CACHE_TTL=300

# Security
ALLOWED_ORIGINS='["https://your-domain.com"]'
SECURE_COOKIES=true
HSTS_MAX_AGE=31536000

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=60

# Monitoring
ENABLE_METRICS=true
LOG_LEVEL=INFO
LOG_FORMAT=json
```

### Database Setup

1. Create database:
```sql
CREATE DATABASE violentutf;
CREATE USER violentutf_user WITH ENCRYPTED PASSWORD 'strong-password';  -- pragma: allowlist secret
GRANT ALL PRIVILEGES ON DATABASE violentutf TO violentutf_user;
```

2. Run migrations:
```bash
alembic upgrade head
```

### Security Considerations

1. **TLS/SSL**
   - Use TLS 1.3+ for all connections
   - Implement proper certificate management
   - Enable HSTS headers

2. **Secrets Management**
   - Never commit secrets to git
   - Use environment variables or secret managers
   - Rotate secrets regularly

3. **Network Security**
   - Implement firewall rules
   - Use private subnets for databases
   - Enable WAF for public endpoints

4. **Access Control**
   - Implement least privilege principle
   - Use service accounts
   - Enable audit logging

## Monitoring Setup

### Prometheus Metrics
Metrics available at `/metrics` endpoint:
- Request count and latency
- Error rates
- Active connections
- Custom business metrics

### Logging
Configure log aggregation:
- JSON format for structured logging
- Include correlation IDs
- Set appropriate log levels
- Implement log retention policies

### Health Checks
- `/api/v1/health` - Basic health
- `/api/v1/ready` - Readiness with dependency checks
- `/api/v1/live` - Liveness probe

## Scaling Guidelines

### Horizontal Scaling
- Stateless design supports multiple instances
- Use load balancer for distribution
- Configure session affinity if needed

### Vertical Scaling
Recommended resources per instance:
- CPU: 2-4 cores
- Memory: 2-4 GB
- Adjust based on load testing

### Auto-scaling
Configure based on:
- CPU utilization (target 70%)
- Memory utilization (target 80%)
- Request rate
- Response time

## Backup and Recovery

### Database Backups
- Daily automated backups
- Point-in-time recovery enabled
- Test restore procedures regularly
- Store backups in separate region

### Disaster Recovery
- Multi-region deployment option
- Database replication
- Cache warming procedures
- Runbook for incidents

## Deployment Checklist

Before deploying to production:

- [ ] All tests passing
- [ ] Security scan completed
- [ ] Dependencies updated
- [ ] Environment variables configured
- [ ] Database migrations tested
- [ ] SSL certificates ready
- [ ] Monitoring configured
- [ ] Backup procedures tested
- [ ] Load testing completed
- [ ] Documentation updated
- [ ] Rollback plan ready
- [ ] Team notified

## Rollback Procedures

1. **Quick Rollback**
   ```bash
   kubectl rollout undo deployment/violentutf-api
   ```

2. **Database Rollback**
   ```bash
   alembic downgrade -1
   ```

3. **Full Rollback**
   - Restore from backup
   - Redeploy previous version
   - Verify functionality

## Performance Tuning

### Application Level
- Enable response caching
- Optimize database queries
- Use connection pooling
- Implement pagination

### Infrastructure Level
- Use CDN for static assets
- Enable compression
- Optimize container size
- Configure keep-alive

### Database Level
- Add appropriate indexes
- Optimize query plans
- Regular VACUUM/ANALYZE
- Monitor slow queries
