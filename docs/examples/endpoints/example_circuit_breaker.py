"""Example endpoints demonstrating circuit breaker usage."""

import asyncio
import random
from typing import Any, Dict, List, Optional, cast

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.decorators.circuit_breaker import (
    cache_operation,
    database_operation,
    external_service,
    protect_with_circuit_breaker,
)
from app.core.external_services import (
    ExternalServiceConfig,
    ServiceRequest,
    ServiceResponse,
    ServiceType,
    get_all_services_health,
    get_service,
    register_service,
)
from app.core.rate_limiting import rate_limit
from app.db.session import get_db
from app.utils.circuit_breaker import (
    CircuitBreakerConfig,
    CircuitBreakerException,
    get_all_circuit_breaker_stats,
    get_circuit_breaker,
)

logger = get_logger(__name__)

router = APIRouter()


# Example models
class WeatherData(BaseModel):
    """Weather data model."""

    city: str
    temperature: float
    conditions: str
    humidity: int
    wind_speed: float


class PaymentRequest(BaseModel):
    """Payment request model."""

    amount: float = Field(..., gt=0, le=1000000)
    currency: str = Field(default="USD", pattern="^[A-Z]{3}$")
    customer_id: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., min_length=1, max_length=500)


class PaymentResponse(BaseModel):
    """Payment response model."""

    transaction_id: str
    status: str
    amount: float
    currency: str
    timestamp: int


class UserSearchResult(BaseModel):
    """User search result model."""

    user_id: int
    username: str
    email: str
    full_name: str


# Initialize demo services
def initialize_demo_services() -> None:
    """Initialize demo external services."""
    # Register a mock weather service
    register_service(
        ExternalServiceConfig(
            name="weather_api",
            service_type=ServiceType.WEATHER,
            base_url="https://api.example-weather.com",
            failure_threshold=3,
            recovery_timeout=30.0,
            health_check_endpoint="/health",
        )
    )

    # Register a mock payment service
    register_service(
        ExternalServiceConfig(
            name="payment_gateway",
            service_type=ServiceType.PAYMENT,
            base_url="https://api.example-payments.com",
            failure_threshold=5,
            recovery_timeout=60.0,
            max_retries=2,
        )
    )

    logger.info("demo_services_initialized")


# Initialize services when module is loaded
initialize_demo_services()


# Simulated external service functions
class SimulatedService:
    """Simulated external service for demonstration."""

    def __init__(self, failure_rate: float = 0.3) -> None:
        """Initialize with configurable failure rate."""
        self.failure_rate = failure_rate
        self.call_count = 0

    async def call(self, delay: float = 0.1) -> Dict[str, Any]:
        """Simulate external service call."""
        self.call_count += 1
        await asyncio.sleep(delay)

        if random.random() < self.failure_rate:
            raise httpx.ConnectError("Simulated connection error")

        return {
            "success": True,
            "call_count": self.call_count,
            "timestamp": asyncio.get_event_loop().time(),
        }


# Create simulated services
weather_service_sim = SimulatedService(failure_rate=0.4)
payment_service_sim = SimulatedService(failure_rate=0.2)
cache_service_sim = SimulatedService(failure_rate=0.1)


@router.get("/weather/{city}")
@rate_limit("api")
@external_service(
    "weather_api",
    failure_threshold=3,
    recovery_timeout=30.0,
    fallback=lambda city: WeatherData(
        city=city,
        temperature=0.0,
        conditions="Service Unavailable",
        humidity=0,
        wind_speed=0.0,
    ),
)
async def get_weather(city: str) -> WeatherData:
    """Get weather data for a city with circuit breaker protection.

    This endpoint demonstrates:
    1. External service call protection
    2. Automatic fallback when circuit is open
    3. Recovery after service is back online

    Try calling this endpoint multiple times to see the circuit breaker in action.
    """
    try:
        # Simulate external API call
        await weather_service_sim.call(delay=0.2)

        # Return mock weather data
        return WeatherData(
            city=city,
            temperature=random.uniform(10, 35),
            conditions=random.choice(["Sunny", "Cloudy", "Rainy", "Partly Cloudy"]),
            humidity=random.randint(30, 90),
            wind_speed=random.uniform(0, 30),
        )

    except httpx.ConnectError as e:
        logger.error("weather_api_error", city=city, error=str(e))
        raise httpx.ConnectError(f"Weather API unavailable: {str(e)}")


@router.post("/payments/process")
@rate_limit("api")
async def process_payment(payment: PaymentRequest) -> PaymentResponse:
    """Process a payment with circuit breaker protection.

    This endpoint demonstrates manual circuit breaker usage for fine-grained control.
    """
    # Get circuit breaker for payment service
    payment_circuit = get_circuit_breaker(
        "payment_processor",
        CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=60.0,
            success_threshold=3,
        ),
    )

    try:
        # Use circuit breaker manually
        async def _process_payment() -> PaymentResponse:
            # Simulate payment processing
            result = await payment_service_sim.call(delay=0.5)

            return PaymentResponse(
                transaction_id=f"TXN_{random.randint(100000, 999999)}",
                status="completed" if result["success"] else "failed",
                amount=payment.amount,
                currency=payment.currency,
                timestamp=int(result["timestamp"]),
            )

        response: PaymentResponse = await payment_circuit.call(_process_payment)

        logger.info(
            "payment_processed",
            transaction_id=response.transaction_id,
            amount=payment.amount,
            customer_id=payment.customer_id,
        )

        return response

    except CircuitBreakerException:
        logger.warning(
            "payment_circuit_open",
            customer_id=payment.customer_id,
            amount=payment.amount,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Payment service temporarily unavailable. Please try again later.",
        )
    except Exception as e:
        logger.error(
            "payment_processing_error",
            error=str(e),
            customer_id=payment.customer_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Payment processing failed",
        )


@router.get("/users/search")
@rate_limit("api")
@database_operation("user_search", failure_threshold=3)
async def search_users(
    query: str,
    db: AsyncSession = Depends(get_db),
    limit: int = 10,
) -> List[UserSearchResult]:
    """Search users with database circuit breaker protection.

    This endpoint demonstrates database operation protection.
    """
    # Simulate database query that might fail
    if random.random() < 0.2:  # 20% failure rate
        raise Exception("Database connection timeout")

    # Return mock results
    results = []
    for i in range(min(limit, 5)):
        results.append(
            UserSearchResult(
                user_id=random.randint(1000, 9999),
                username=f"user_{query}_{i}",
                email=f"user{i}@example.com",
                full_name=f"User {query.title()} {i}",
            )
        )

    return results


@router.get("/cache/get/{key}")
@rate_limit("api")
@cache_operation("redis", failure_threshold=3, fallback_to_none=True)
async def get_cached_value(key: str) -> Optional[Dict[str, Any]]:
    """Get value from cache with circuit breaker protection.

    This endpoint demonstrates cache operation protection with automatic fallback to None.
    """
    # Simulate cache lookup
    result = await cache_service_sim.call(delay=0.05)

    if result["success"]:
        return {
            "key": key,
            "value": f"cached_value_{random.randint(1000, 9999)}",
            "ttl": random.randint(60, 3600),
        }

    return None


@router.get("/circuit-breakers/stats")
@rate_limit("api")
async def get_circuit_breaker_stats() -> Dict[str, Any]:
    """Get statistics for all circuit breakers.

    This endpoint shows the current state of all circuit breakers in the system.
    """
    stats = await get_all_circuit_breaker_stats()

    # Add service health information
    service_health = await get_all_services_health()

    return {
        "circuit_breakers": stats,
        "service_health": service_health,
        "summary": {
            "total_circuits": len(stats),
            "open_circuits": sum(1 for cb in stats.values() if cb["state"] == "open"),
            "half_open_circuits": sum(1 for cb in stats.values() if cb["state"] == "half_open"),
            "closed_circuits": sum(1 for cb in stats.values() if cb["state"] == "closed"),
        },
    }


@router.post("/circuit-breakers/{circuit_name}/reset")
@rate_limit("api")
async def reset_circuit_breaker(circuit_name: str) -> Dict[str, str]:
    """Manually reset a circuit breaker.

    This endpoint allows manual intervention to reset a circuit breaker.
    """
    try:
        circuit = get_circuit_breaker(circuit_name)
        await circuit.reset()

        logger.info(
            "circuit_breaker_reset_manual",
            circuit_name=circuit_name,
        )

        return {
            "status": "success",
            "message": f"Circuit breaker '{circuit_name}' has been reset",
        }

    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Circuit breaker '{circuit_name}' not found",
        )


@router.get("/demo/cascade-failure")
@rate_limit("api")
async def demo_cascade_failure() -> Dict[str, Any]:
    """Demonstrate cascade failure prevention.

    This endpoint shows how circuit breakers prevent cascade failures
    by calling multiple services that depend on each other.
    """
    results: Dict[str, Any] = {
        "services_called": [],
        "failures": [],
        "circuit_states": {},
    }

    # Try weather service
    try:
        weather = await get_weather("London")
        results["services_called"].append(
            {
                "service": "weather",
                "status": "success",
                "data": weather.model_dump(),
            }
        )
    except Exception as e:
        results["failures"].append(
            {
                "service": "weather",
                "error": str(e),
                "type": type(e).__name__,
            }
        )

    # Try payment service (simulated)
    payment_circuit = get_circuit_breaker("payment_demo")
    try:

        async def simulate_payment() -> Dict[str, Any]:
            await payment_service_sim.call()
            return {"status": "success", "amount": 100.0}

        payment_result: Dict[str, Any] = await payment_circuit.call(simulate_payment)
        results["services_called"].append(
            {
                "service": "payment",
                "status": "success",
                "data": payment_result,
            }
        )
    except CircuitBreakerException:
        results["failures"].append(
            {
                "service": "payment",
                "error": "Circuit breaker open - preventing cascade failure",
                "type": "CircuitBreakerException",
            }
        )
    except Exception as e:
        results["failures"].append(
            {
                "service": "payment",
                "error": str(e),
                "type": type(e).__name__,
            }
        )

    # Get circuit breaker states
    all_stats = await get_all_circuit_breaker_stats()
    for name, stats in all_stats.items():
        if "demo" in name or "weather" in name or "payment" in name:
            results["circuit_states"][name] = {
                "state": stats["state"],
                "failure_count": stats["failure_count"],
                "success_count": stats["success_count"],
            }

    return results


@router.get("/demo/recovery")
@rate_limit("api")
async def demo_recovery_behavior() -> Dict[str, Any]:
    """Demonstrate circuit breaker recovery behavior.

    This endpoint shows how circuit breakers transition from:
    CLOSED -> OPEN (after failures) -> HALF_OPEN (after timeout) -> CLOSED (after successes)
    """
    # Create a service that fails initially then recovers
    recovery_service = SimulatedService(failure_rate=0.0)  # Start with no failures
    circuit = get_circuit_breaker(
        "recovery_demo",
        CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=5.0,  # Short timeout for demo
            success_threshold=2,
        ),
    )

    timeline: List[Dict[str, Any]] = []

    # Phase 1: Working normally (CLOSED)
    try:
        await circuit.call(recovery_service.call)  # type: ignore[arg-type]
        timeline.append(
            {
                "phase": "normal_operation",
                "state": circuit.state.value,
                "result": "success",
            }
        )
    except Exception as e:
        timeline.append(
            {
                "phase": "normal_operation",
                "state": circuit.state.value,
                "result": "failure",
                "error": str(e),
            }
        )

    # Phase 2: Introduce failures (CLOSED -> OPEN)
    recovery_service.failure_rate = 1.0  # Always fail
    for i in range(3):
        try:
            await circuit.call(recovery_service.call)  # type: ignore[arg-type]
        except CircuitBreakerException:
            timeline.append(
                {
                    "phase": "circuit_open",
                    "attempt": i + 1,
                    "state": circuit.state.value,
                    "result": "circuit_breaker_prevented_call",
                }
            )
        except Exception:
            timeline.append(
                {
                    "phase": "failing",
                    "attempt": i + 1,
                    "state": circuit.state.value,
                    "result": "service_failure",
                }
            )

    # Phase 3: Wait for recovery timeout
    timeline.append(
        {
            "phase": "waiting_for_recovery",
            "wait_seconds": 5,
            "state": circuit.state.value,
        }
    )
    await asyncio.sleep(5.5)

    # Phase 4: Service recovers (HALF_OPEN -> CLOSED)
    recovery_service.failure_rate = 0.0  # Service is healthy again
    for i in range(3):
        try:
            await circuit.call(recovery_service.call)  # type: ignore[arg-type]
            timeline.append(
                {
                    "phase": "recovery",
                    "attempt": i + 1,
                    "state": circuit.state.value,
                    "result": "success",
                }
            )
        except Exception as e:
            timeline.append(
                {
                    "phase": "recovery",
                    "attempt": i + 1,
                    "state": circuit.state.value,
                    "result": "failure",
                    "error": str(e),
                }
            )

    return {
        "demonstration": "Circuit Breaker Recovery Behavior",
        "timeline": timeline,
        "final_state": circuit.state.value,
        "final_stats": circuit.get_stats(),
    }
