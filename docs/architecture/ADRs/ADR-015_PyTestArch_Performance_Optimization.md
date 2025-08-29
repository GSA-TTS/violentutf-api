# ADR-015: PyTestArch Performance Optimization and Caching Strategy

**Status:** Accepted
**Date:** 2025-08-26
**Authors:** Claude Code
**Supersedes:** None
**Related to:** Issue #70, ADR-010

## Context

The current PyTestArch dependency compliance tests exhibit severe performance issues:

1. **Individual subprocess calls**: Each pip show command takes ~0.2s, with 176 packages = ~35s minimum
2. **No caching mechanism**: Every test run performs full dependency scan from scratch
3. **Synchronous processing**: All operations run sequentially without parallelization
4. **Network dependencies**: License validation requires PyPI API calls without fallbacks
5. **Memory inefficiency**: No reuse of package metadata between test runs
6. **CI/CD timeouts**: Current execution time >120s causes pipeline failures

These performance issues block effective architectural testing and violate our CI/CD performance requirements (<10s for dependency tests, <30s for full architectural suite).

## Decision

We will implement a multi-layered performance optimization strategy:

### 1. Multi-Level Caching Architecture

```python
# Three-tier caching strategy
class DependencyCache:
    def __init__(self):
        self.memory_cache = LRUCache(maxsize=1000)    # L1: In-memory
        self.file_cache = FileCacheManager()          # L2: File-based with TTL
        self.shared_cache = RedisCacheManager()       # L3: Shared across runs
```

**Cache Levels:**
- **L1 (Memory)**: Process-lifetime cache for immediate reuse within test session
- **L2 (File)**: Persistent cache with 24h TTL for local development
- **L3 (Redis)**: Shared cache for CI/CD environments with 7d TTL

**Cache Keys:**
```python
# Versioned cache keys that invalidate on requirements changes
cache_key = f"dep_scan:{requirements_hash}:{package}:{version}"
```

### 2. Batch Processing Strategy

Replace individual subprocess calls with bulk operations:

```python
# Single pip list call instead of N individual calls
async def get_all_packages() -> Dict[str, PackageInfo]:
    result = await asyncio.create_subprocess_exec('pip', 'list', '--format=json')
    return {pkg['name']: PackageInfo(**pkg) for pkg in json.loads(result.stdout)}

# Bulk PyPI metadata retrieval
async def get_bulk_metadata(packages: List[str]) -> Dict[str, dict]:
    async with httpx.AsyncClient() as client:
        tasks = [client.get(f"https://pypi.org/pypi/{pkg}/json") for pkg in packages]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
```

### 3. Parallel Execution Framework

Implement asynchronous processing for I/O bound operations:

```python
# Parallel vulnerability scanning
async def scan_vulnerabilities_parallel(packages: List[str]) -> List[VulnResult]:
    semaphore = asyncio.Semaphore(10)  # Limit concurrent requests
    async def scan_package(pkg: str):
        async with semaphore:
            return await vulnerability_scanner.scan(pkg)

    tasks = [scan_package(pkg) for pkg in packages]
    return await asyncio.gather(*tasks, return_exceptions=True)
```

### 4. Intelligent Cache Management

```python
class CacheManager:
    def __init__(self):
        self.ttl_config = {
            'package_metadata': 86400,    # 24 hours
            'license_info': 604800,       # 7 days (stable)
            'vulnerability_data': 3600,   # 1 hour (security-critical)
            'dependency_tree': 1800,      # 30 minutes
        }

    async def get_with_fallback(self, key: str, fetcher: Callable) -> Any:
        # Try L1 -> L2 -> L3 -> Network/Computation
        for cache_layer in [self.memory, self.file, self.redis]:
            if value := await cache_layer.get(key):
                return value

        # Fetch and populate all cache layers
        value = await fetcher()
        await self.populate_all_caches(key, value)
        return value
```

### 5. Performance Monitoring and Metrics

```python
@performance_tracker
class DependencyScanner:
    async def scan_dependencies(self) -> ScanResult:
        with PerformanceMetrics("dependency_scan") as metrics:
            # Track cache hit rates, execution time, memory usage
            metrics.track_cache_hits(self.cache.hit_rate)
            metrics.track_execution_time()
            metrics.track_memory_usage()
```

## Performance Targets

- **Dependency compliance test**: <10 seconds (from >120s)
- **Full architectural test suite**: <30 seconds
- **Cache hit rate**: >80% for repeated runs
- **Memory usage**: <512MB peak during testing
- **CI/CD success rate**: >99% (eliminate timeouts)

## Implementation Strategy

### Phase 1: Caching Infrastructure (Days 1-3)
1. Implement multi-level cache system
2. Add TTL-based cache invalidation
3. Create cache versioning for requirements changes
4. Add cache warming utilities

### Phase 2: Batch Processing (Days 4-5)
1. Replace individual pip calls with bulk operations
2. Implement bulk PyPI metadata retrieval
3. Add memoization for package resolution
4. Optimize requirements.txt parsing

### Phase 3: Parallel Execution (Week 2)
1. Implement async vulnerability scanning
2. Add concurrent license validation
3. Create performance monitoring framework
4. Add regression detection

## Consequences

### Positive
- **Dramatic performance improvement**: 10x+ speed improvement expected
- **CI/CD reliability**: Eliminates timeout-related failures
- **Developer productivity**: Faster feedback loops
- **Resource efficiency**: Lower CPU/memory usage through caching
- **Offline capability**: File-based caching enables offline testing
- **Scalability**: Architecture supports larger dependency sets

### Negative
- **Implementation complexity**: Multi-level caching requires careful design
- **Cache invalidation complexity**: Must handle stale cache scenarios
- **Storage requirements**: File/Redis cache requires disk/memory space
- **Dependency on external services**: PyPI API calls introduce network dependency
- **Initial cache warming cost**: First run may be slower while populating caches

### Risk Mitigation Strategies
1. **Cache coherency**: Hash-based versioning ensures cache validity
2. **Graceful degradation**: Fallback to direct API calls if cache fails
3. **Circuit breaker**: Fail fast on repeated external API failures
4. **Memory limits**: LRU eviction prevents memory exhaustion
5. **Monitoring**: Performance metrics detect regressions early

## Compliance with Existing ADRs

- **ADR-010 (Dependencies)**: Maintains all security and compliance validation
- **ADR-008 (Logging)**: Comprehensive performance logging and metrics
- **ADR-007 (Async Processing)**: Leverages async patterns for I/O operations

## Success Metrics

1. **Performance**: Dependency scan <10s, full suite <30s
2. **Reliability**: >99% CI/CD success rate
3. **Efficiency**: >80% cache hit rate on repeated runs
4. **Quality**: Zero reduction in detection accuracy
5. **Maintainability**: Clean separation of concerns, testable components

## Rollback Plan

Feature flags enable gradual rollout and immediate rollback:
```python
@feature_flag("optimized_dependency_scanning", default=False)
async def scan_dependencies():
    if feature_enabled("optimized_dependency_scanning"):
        return await optimized_scanner.scan()
    else:
        return await legacy_scanner.scan()
```

## Implementation Notes

This ADR enables Issue #70 implementation by providing:
- Clear architectural patterns for performance optimization
- Specific technical decisions for caching strategy
- Performance benchmarks and success criteria
- Risk mitigation and rollback procedures
- Compliance with existing architectural constraints
