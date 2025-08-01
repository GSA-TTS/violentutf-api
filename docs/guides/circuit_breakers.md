# Circuit Breakers Guide

Circuit breakers protect your API from cascading failures by monitoring external service calls and preventing requests when services are unavailable.

## Overview

The circuit breaker pattern provides:

- **Failure Detection** - Monitors external calls for failures
- **Fast Failure** - Prevents calls when service is down
- **Automatic Recovery** - Tests service health periodically
- **Cascade Prevention** - Stops failures from spreading
- **Resource Protection** - Prevents overwhelming failing services

## Circuit Breaker States

### 1. CLOSED (Normal Operation)
- All requests pass through
- Failures are counted
- Opens when failure threshold is reached

### 2. OPEN (Failing Fast)
- All requests fail immediately
- No calls to the external service
- Waits for recovery timeout

### 3. HALF_OPEN (Testing Recovery)
- Limited requests allowed through
- Success moves to CLOSED
- Failure returns to OPEN

## Basic Usage

### Using Decorators

```python
from app.core.decorators.circuit_breaker import external_service

@external_service(
    "weather_api",
    failure_threshold=3,
    recovery_timeout=30.0,
    fallback=lambda: {"status": "unavailable"}
)
async def get_weather_data():
    async with httpx.AsyncClient() as client:
        response = await client.get("https://api.weather.com/current")
        return response.json()
```

### Using External Service Client

```python
from app.core.external_services import (
    ExternalServiceConfig,
    ExternalServiceClient,
    ServiceRequest,
    ServiceType
)

# Configure service
config = ExternalServiceConfig(
    name="payment_gateway",
    service_type=ServiceType.PAYMENT,
    base_url="https://api.payments.com",
    failure_threshold=5,
    recovery_timeout=60.0,
    max_retries=3
)

# Create client
client = ExternalServiceClient(config)

# Make request
request = ServiceRequest(
    method="POST",
    path="/charge",
    json_data={"amount": 99.99, "currency": "USD"}
)

try:
    response = await client.request(request)
except CircuitBreakerException:
    # Handle circuit open
    return {"error": "Payment service unavailable"}
```

## Decorators

### @external_service

Protect external API calls:

```python
@external_service(
    "github_api",
    failure_threshold=3,
    recovery_timeout=30.0,
    timeout=10.0,
    fallback=lambda repo: {"stars": 0, "status": "unavailable"}
)
async def get_repo_stats(repo: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.get(f"https://api.github.com/repos/{repo}")
        return response.json()
```

### @database_operation

Protect database operations:

```python
@database_operation("user_search", failure_threshold=5)
async def search_users(db: AsyncSession, query: str) -> List[User]:
    return await db.execute(
        select(User).where(User.name.ilike(f"%{query}%"))
    ).scalars().all()
```

### @cache_operation

Protect cache operations with fallback:

```python
@cache_operation("redis", fallback_to_none=True)
async def get_cached_data(key: str) -> Optional[dict]:
    return await redis_client.get(key)
```

### @message_queue

Protect message queue operations:

```python
@message_queue("rabbitmq", failure_threshold=5)
async def publish_event(event: dict) -> bool:
    return await rabbitmq.publish("events", event)
```

## Configuration

### CircuitBreakerConfig

```python
from app.utils.circuit_breaker import CircuitBreakerConfig

config = CircuitBreakerConfig(
    failure_threshold=5,      # Failures before opening
    recovery_timeout=60.0,    # Seconds before half-open
    success_threshold=3,      # Successes to close from half-open
    timeout=30.0,            # Timeout for individual calls
    expected_exception=Exception  # Exceptions that count as failures
)
```

### ExternalServiceConfig

```python
config = ExternalServiceConfig(
    name="stripe_api",
    service_type=ServiceType.PAYMENT,
    base_url="https://api.stripe.com",

    # Circuit breaker settings
    failure_threshold=5,
    recovery_timeout=60.0,
    success_threshold=3,

    # Retry settings
    max_retries=3,
    retry_delay=1.0,
    retry_backoff=2.0,

    # Monitoring
    enable_metrics=True,
    health_check_endpoint="/health",
    health_check_interval=300.0
)
```

## Service Registry

### Registering Services

```python
from app.core.external_services import register_service

# Register payment service
payment_client = register_service(
    ExternalServiceConfig(
        name="payment_service",
        service_type=ServiceType.PAYMENT,
        base_url="https://payments.example.com",
        headers={"X-API-Key": settings.PAYMENT_API_KEY}
    )
)

# Register email service
email_client = register_service(
    ExternalServiceConfig(
        name="email_service",
        service_type=ServiceType.EMAIL,
        base_url="https://api.sendgrid.com",
        failure_threshold=3,
        recovery_timeout=30.0
    )
)
```

### Using Registered Services

```python
from app.core.external_services import get_service

# Get service by name
payment_service = get_service("payment_service")

if payment_service:
    response = await payment_service.request(
        ServiceRequest(
            method="POST",
            path="/v1/charges",
            json_data={"amount": 5000, "currency": "usd"}
        )
    )
```

## Monitoring

### Circuit Breaker Statistics

```python
from app.utils.circuit_breaker import get_all_circuit_breaker_stats

# Get all circuit breaker stats
stats = await get_all_circuit_breaker_stats()

for name, cb_stats in stats.items():
    print(f"{name}: {cb_stats['state']} - "
          f"Failures: {cb_stats['failure_count']}, "
          f"Successes: {cb_stats['success_count']}")
```

### Service Health

```python
from app.core.external_services import get_all_services_health

# Check health of all services
health_status = await get_all_services_health()

for service, health in health_status.items():
    print(f"{service}: {health.value}")
```

### Manual Circuit Control

```python
from app.utils.circuit_breaker import get_circuit_breaker

# Get specific circuit breaker
circuit = get_circuit_breaker("payment_service")

# Check state
if circuit.is_open():
    print("Circuit is open - service unavailable")

# Reset circuit manually (after fixing issues)
await circuit.reset()
```

## Best Practices

### 1. Choose Appropriate Thresholds

```python
# For critical services - be more tolerant
@external_service(
    "critical_api",
    failure_threshold=10,    # More failures allowed
    recovery_timeout=120.0,  # Longer recovery time
    timeout=60.0            # Longer timeout
)

# For non-critical services - fail fast
@external_service(
    "optional_api",
    failure_threshold=2,     # Fail quickly
    recovery_timeout=30.0,   # Try recovery sooner
    timeout=5.0             # Short timeout
)
```

### 2. Implement Fallbacks

```python
# Static fallback
@external_service(
    "product_recommendations",
    fallback=lambda user_id: []  # Empty recommendations
)
async def get_recommendations(user_id: int) -> List[Product]:
    # API call here
    pass

# Dynamic fallback
def recommendation_fallback(user_id: int) -> List[Product]:
    # Return cached or default recommendations
    cached = cache.get(f"recommendations:{user_id}")
    return cached or get_popular_products()

@external_service(
    "product_recommendations",
    fallback=recommendation_fallback
)
```

### 3. Monitor and Alert

```python
# Create monitoring endpoint
@router.get("/health/circuits")
async def circuit_health():
    stats = await get_all_circuit_breaker_stats()

    unhealthy = [
        name for name, s in stats.items()
        if s["state"] in ["open", "half_open"]
    ]

    if unhealthy:
        # Send alerts
        await send_alert(f"Circuit breakers open: {unhealthy}")

    return {
        "healthy": len(unhealthy) == 0,
        "circuits": stats,
        "unhealthy_circuits": unhealthy
    }
```

### 4. Test Circuit Breakers

```python
# Test circuit breaker behavior
@pytest.mark.asyncio
async def test_circuit_breaker_opens():
    circuit = get_circuit_breaker("test_service")

    # Force failures
    for _ in range(5):
        with pytest.raises(ServiceError):
            await failing_service_call()

    # Circuit should be open
    assert circuit.is_open()

    # Next call should fail fast
    with pytest.raises(CircuitBreakerException):
        await failing_service_call()
```

## Common Patterns

### Cascading Service Calls

```python
@external_service("service_a", fallback=lambda: None)
async def call_service_a():
    # First service call
    pass

@external_service("service_b", fallback=lambda: None)
async def call_service_b():
    # Second service call
    pass

async def orchestrate_services():
    # Circuit breakers prevent cascade failures
    result_a = await call_service_a()
    if result_a:
        result_b = await call_service_b()
        return combine_results(result_a, result_b)
    return None
```

### Batch Operations

```python
@external_service(
    "batch_processor",
    failure_threshold=2,  # Fail fast for batch ops
    fallback=lambda items: {"processed": 0, "failed": len(items)}
)
async def process_batch(items: List[dict]) -> dict:
    # Process batch of items
    pass
```

### Health Check Integration

```python
@router.get("/health")
async def health_check():
    # Include circuit breaker health
    circuit_stats = await get_all_circuit_breaker_stats()
    service_health = await get_all_services_health()

    # Overall health
    healthy = all(
        s["state"] == "closed"
        for s in circuit_stats.values()
    )

    return {
        "status": "healthy" if healthy else "degraded",
        "circuits": circuit_stats,
        "services": service_health
    }
```

## Troubleshooting

### Circuit Won't Close

1. Check success threshold is being met
2. Verify service is actually healthy
3. Check for clock skew affecting timeouts
4. Manually reset if necessary

### Too Many False Positives

1. Increase failure threshold
2. Increase timeout values
3. Check network latency
4. Implement retry logic

### Performance Impact

1. Circuit breaker checks are fast (microseconds)
2. Use appropriate timeout values
3. Monitor circuit breaker overhead
4. Consider caching for read operations

## See Also

- [Retry Strategies](./retry_strategies.md)
- [Error Handling](./error_handling.md)
- [Monitoring Guide](./monitoring.md)
- [External API Integration](./external_apis.md)
