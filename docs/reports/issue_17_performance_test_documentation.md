# Issue #17 Performance Test Documentation

## Overview

This document provides comprehensive documentation for the performance and load tests created for Issue #17: Setup migrations and repository pattern. These tests ensure that the database layer implementation meets performance requirements under various load conditions.

## Test Suite Structure

### 1. Connection Pooling Load Tests (`test_connection_pooling_load_fixed.py`)

Tests the database connection pooling mechanism under various load scenarios.

#### Tests Included:

##### a) Normal Load Test
- **Concurrent Connections**: 20
- **Iterations per Connection**: 10
- **Total Requests**: 200
- **Performance Targets**:
  - Error rate < 1%
  - Average response time < 100ms
  - P95 response time < 200ms

##### b) High Load Test
- **Concurrent Connections**: 100
- **Iterations per Connection**: 5
- **Total Requests**: 500
- **Performance Targets**:
  - Error rate < 5%
  - Average response time < 500ms

##### c) Pool Exhaustion Test
- Tests behavior when connection requests exceed pool size
- Verifies queuing mechanism works correctly
- Ensures no connection leaks under pressure

##### d) Connection Recycling Test
- Verifies connections are reused from pool
- Tracks unique connection IDs (PostgreSQL only)
- Ensures pool size limits are respected

##### e) Pool Monitoring Test
- Verifies pool statistics are accessible
- Monitors pool health metrics

### 2. Retry Logic Load Tests (`test_retry_logic_load.py`)

Tests the retry mechanism under various failure scenarios.

#### Tests Included:

##### a) Transient Failures Test
- Simulates random database failures (30% failure rate)
- Tests exponential backoff implementation
- Verifies recovery rate exceeds failure rate

##### b) Circuit Breaker Integration Test
- Tests circuit breaker behavior under sustained failures
- Verifies circuit trips after threshold
- Tests recovery mechanism

##### c) Timeout Handling Test
- Tests behavior with slow operations
- Verifies timeout enforcement
- Ensures resource cleanup after timeouts

##### d) Exponential Backoff Test
- Verifies retry delays follow exponential pattern
- Tests: 0.1s, 0.2s, 0.4s, 0.8s progression
- Ensures proper delay calculation

##### e) Retry Storm Test
- Simulates many concurrent failing operations
- Tests system stability under retry storms
- Verifies eventual consistency

### 3. Session Leak Prevention Tests (`test_session_leak_prevention.py`)

Ensures database sessions are properly managed and don't leak resources.

#### Tests Included:

##### a) Normal Operations Cleanup Test
- Executes 100 operations
- Tracks session lifecycle with weak references
- Verifies all sessions are closed

##### b) Exception Handling Cleanup Test
- Tests cleanup when operations raise exceptions
- Simulates various error scenarios
- Ensures sessions close despite errors

##### c) Concurrent Session Management Test
- Tests peak session usage under load
- Verifies reasonable concurrent session count
- Ensures cleanup after concurrent operations

##### d) Memory Stability Test
- Runs 1000 operations in batches
- Monitors RSS memory growth
- Target: < 50MB growth

##### e) Connection Pool Leak Prevention Test
- Monitors pool's checked-out connections
- Ensures connections return to pool
- Verifies no connection leaks

##### f) Context Manager Tracking Test
- Tracks session creation and closure
- Verifies context manager correctness
- Ensures 1:1 create/close ratio

##### g) Tracemalloc Memory Tracking Test
- Uses Python's tracemalloc for detailed analysis
- Identifies memory allocation hotspots
- Verifies peak memory < 100MB

### 4. Performance Benchmark Suite (`test_performance_benchmarks.py`)

Comprehensive benchmarks for repository operations.

#### Benchmark Categories:

##### a) CRUD Operations
- Create User: Target < 50ms average
- Get by ID: Target < 10ms average
- Update User: Target < 20ms average
- Soft Delete: Target < 20ms average
- Restore: Target < 20ms average

##### b) Query Optimization
- Get by Username: Target < 20ms
- Get by Email: Target < 20ms
- Complex queries with filters
- Aggregation queries

##### c) Pagination Performance
- Tests with page sizes: 10, 25, 50, 100
- Verifies linear scaling
- Ensures large pages don't degrade significantly

##### d) Bulk Operations
- Compares individual vs bulk operations
- Tests with sizes: 10, 50, 100
- Measures per-item overhead

##### e) Complex Queries
- Tests joins (User + API Keys)
- Aggregation queries
- Multi-table operations

##### f) Concurrent Operations
- Tests with concurrency: 1, 5, 10, 20
- Separate read and write benchmarks
- Verifies sub-linear scaling

##### g) Transaction Performance
- Tests transaction sizes: 1, 5, 10, 20
- Measures commit overhead
- Includes audit logging

## Performance Metrics Collected

### Response Time Metrics
- Minimum response time
- Average response time
- Median (P50) response time
- 95th percentile (P95) response time
- 99th percentile (P99) response time
- Maximum response time
- Standard deviation

### Throughput Metrics
- Total requests processed
- Successful requests
- Failed requests
- Error rate
- Operations per second

### Resource Metrics
- Memory usage (RSS, VMS)
- Connection pool utilization
- Active session count
- Circuit breaker state

## Running Performance Tests

### Prerequisites
```bash
# Install required packages
pip install psutil psycopg2-binary

# Ensure database is configured
export DATABASE_URL="postgresql://user:pass@localhost/testdb"  # pragma: allowlist secret
```

### Running Individual Tests
```bash
# Connection pooling tests
pytest tests/performance/test_connection_pooling_load_fixed.py -v -s

# Retry logic tests
pytest tests/performance/test_retry_logic_load.py -v -s

# Session leak tests
pytest tests/performance/test_session_leak_prevention.py -v -s

# Benchmark suite
pytest tests/performance/test_performance_benchmarks.py -v -s
```

### Running All Tests
```bash
python tests/performance/run_performance_tests.py
```

## Interpreting Results

### Success Criteria

#### Connection Pooling
- ✅ Normal load: < 1% error rate, < 100ms avg response
- ✅ High load: < 5% error rate, < 500ms avg response
- ✅ Pool recycling working correctly
- ✅ No connection leaks detected

#### Retry Logic
- ✅ Recovery rate > failure rate
- ✅ Circuit breaker trips at threshold
- ✅ Exponential backoff working correctly
- ✅ System recovers from retry storms

#### Session Management
- ✅ Zero leaked sessions
- ✅ Memory growth < 50MB over 1000 operations
- ✅ All sessions cleaned up properly
- ✅ Context managers working correctly

#### Performance Benchmarks
- ✅ CRUD operations meet latency targets
- ✅ Query optimization effective
- ✅ Pagination scales linearly
- ✅ Concurrent operations scale sub-linearly

### Warning Signs

1. **High Error Rates**: > 5% errors under normal load
2. **Memory Leaks**: Continuous memory growth
3. **Session Leaks**: Active sessions after operations
4. **Pool Exhaustion**: Frequent pool timeout errors
5. **Circuit Breaker Issues**: Not recovering after failures

## Configuration Tuning

Based on test results, consider tuning:

### Connection Pool Settings
```python
DATABASE_POOL_SIZE = 10  # Increase for high concurrency
DATABASE_MAX_OVERFLOW = 5  # Allow temporary connections
DATABASE_POOL_TIMEOUT = 30  # Timeout for getting connection
```

### Circuit Breaker Settings
```python
CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5  # Failures before trip
CIRCUIT_BREAKER_RECOVERY_TIMEOUT = 30  # Seconds before retry
CIRCUIT_BREAKER_EXPECTED_EXCEPTION = OperationalError
```

### Retry Settings
```python
MAX_RETRIES = 3
RETRY_DELAY = 0.1  # Base delay in seconds
RETRY_BACKOFF = 2  # Exponential backoff multiplier
```

## Best Practices

1. **Run Tests Regularly**: Include in CI/CD pipeline
2. **Baseline Performance**: Establish baseline metrics
3. **Monitor Trends**: Track performance over time
4. **Test Under Load**: Simulate production conditions
5. **Profile Bottlenecks**: Use results to guide optimization

## Troubleshooting

### Common Issues

1. **Database Not Configured**
   - Ensure DATABASE_URL is set
   - Install database drivers (psycopg2-binary)

2. **Import Errors**
   - Check Python path includes project root
   - Ensure all dependencies installed

3. **Timeout Errors**
   - Increase test timeouts for slow systems
   - Check database connectivity

4. **Memory Issues**
   - Run tests individually if memory limited
   - Use smaller test datasets

## Conclusion

The performance test suite provides comprehensive coverage of:
- Connection pooling efficiency
- Retry logic resilience
- Session leak prevention
- Overall system performance

All tests are designed to ensure the repository pattern implementation meets production requirements for reliability, performance, and resource management.
