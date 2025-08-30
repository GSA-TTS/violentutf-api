#!/usr/bin/env python3
"""
Health check script for services in Docker containers.
Implements ADR-012 ASR-5 requirements for service health checking.
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class HealthChecker:
    """Base class for service health checks."""

    def __init__(self, timeout: int = 30):
        """
        Initialize health checker.

        Args:
            timeout: Maximum time to wait for service to be healthy
        """
        self.timeout = timeout
        self.start_time = time.time()

    def check(self) -> Dict[str, Any]:
        """
        Perform health check.

        Returns:
            Dictionary with health status information
        """
        raise NotImplementedError("Subclasses must implement check()")

    def wait_until_healthy(self, interval: int = 2) -> bool:
        """
        Wait until service is healthy or timeout is reached.

        Args:
            interval: Time to wait between checks

        Returns:
            True if service became healthy, False if timeout reached
        """
        while (time.time() - self.start_time) < self.timeout:
            try:
                result = self.check()
                if result.get("status") == "healthy":
                    logger.info(f"Service is healthy after {time.time() - self.start_time:.1f}s")
                    return True
                logger.debug(f"Service not ready: {result}")
            except Exception as e:
                logger.debug(f"Health check failed: {e}")

            time.sleep(interval)

        logger.error(f"Service did not become healthy within {self.timeout}s")
        return False


class PostgreSQLHealthChecker(HealthChecker):
    """Health checker for PostgreSQL database."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        database: str = "testdb",
        user: str = "test",
        password: str = "test",
        timeout: int = 30,
    ):
        """Initialize PostgreSQL health checker."""
        super().__init__(timeout)
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password

    def check(self) -> Dict[str, Any]:
        """Check PostgreSQL health."""
        try:
            import psycopg2

            conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password,
                connect_timeout=5,
            )

            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            cursor.close()
            conn.close()

            if result and result[0] == 1:
                return {
                    "status": "healthy",
                    "service": "postgresql",
                    "message": f"Connected to {self.database}@{self.host}:{self.port}",
                }
            else:
                return {
                    "status": "unhealthy",
                    "service": "postgresql",
                    "message": "Query check failed",
                }

        except Exception as e:
            return {"status": "unhealthy", "service": "postgresql", "message": str(e)}


class RedisHealthChecker(HealthChecker):
    """Health checker for Redis."""

    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0, timeout: int = 10):
        """Initialize Redis health checker."""
        super().__init__(timeout)
        self.host = host
        self.port = port
        self.db = db

    def check(self) -> Dict[str, Any]:
        """Check Redis health."""
        try:
            import redis

            r = redis.Redis(host=self.host, port=self.port, db=self.db, socket_connect_timeout=5)

            if r.ping():
                # Test basic operations
                test_key = f"health_check_{int(time.time())}"
                r.set(test_key, "OK", ex=10)
                value = r.get(test_key)
                r.delete(test_key)

                if value == b"OK":
                    return {
                        "status": "healthy",
                        "service": "redis",
                        "message": f"Connected to Redis@{self.host}:{self.port}",
                    }

            return {
                "status": "unhealthy",
                "service": "redis",
                "message": "Redis ping failed",
            }

        except Exception as e:
            return {"status": "unhealthy", "service": "redis", "message": str(e)}


class APIHealthChecker(HealthChecker):
    """Health checker for API service."""

    def __init__(self, base_url: str = "http://localhost:8000", timeout: int = 45):
        """Initialize API health checker."""
        super().__init__(timeout)
        self.base_url = base_url.rstrip("/")

    def check(self) -> Dict[str, Any]:
        """Check API health."""
        try:
            import requests

            response = requests.get(f"{self.base_url}/health", timeout=10)

            if response.status_code == 200:
                health_data = response.json()

                # Check dependencies if provided
                dependencies_healthy = True
                if "dependencies" in health_data:
                    for dep_name, dep_status in health_data["dependencies"].items():
                        if dep_status.get("status") != "healthy":
                            dependencies_healthy = False
                            break

                if health_data.get("status") == "healthy" and dependencies_healthy:
                    return {
                        "status": "healthy",
                        "service": "api",
                        "message": f"API is healthy at {self.base_url}",
                        "details": health_data,
                    }
                else:
                    return {
                        "status": "degraded",
                        "service": "api",
                        "message": "API is running but some dependencies are unhealthy",
                        "details": health_data,
                    }
            else:
                return {
                    "status": "unhealthy",
                    "service": "api",
                    "message": f"API returned status code {response.status_code}",
                }

        except Exception as e:
            return {"status": "unhealthy", "service": "api", "message": str(e)}


class CeleryHealthChecker(HealthChecker):
    """Health checker for Celery workers."""

    def __init__(self, broker_url: str = "redis://localhost:6379/1", timeout: int = 30):
        """Initialize Celery health checker."""
        super().__init__(timeout)
        self.broker_url = broker_url

    def check(self) -> Dict[str, Any]:
        """Check Celery worker health."""
        try:
            from celery import Celery

            # Create Celery app instance
            app = Celery("health_check", broker=self.broker_url)

            # Get worker stats
            inspector = app.control.inspect()
            stats = inspector.stats()

            if stats:
                active_workers = list(stats.keys())
                return {
                    "status": "healthy",
                    "service": "celery",
                    "message": f"Found {len(active_workers)} active workers",
                    "workers": active_workers,
                }
            else:
                return {
                    "status": "unhealthy",
                    "service": "celery",
                    "message": "No active workers found",
                }

        except Exception as e:
            return {"status": "unhealthy", "service": "celery", "message": str(e)}


class CompositeHealthChecker:
    """Composite health checker for multiple services."""

    def __init__(self, checkers: Dict[str, HealthChecker]):
        """
        Initialize composite health checker.

        Args:
            checkers: Dictionary of service name to health checker
        """
        self.checkers = checkers

    def check_all(self) -> Dict[str, Any]:
        """
        Check health of all services.

        Returns:
            Composite health status
        """
        results = {}
        overall_status = "healthy"

        for name, checker in self.checkers.items():
            try:
                result = checker.check()
                results[name] = result

                if result["status"] == "unhealthy":
                    overall_status = "unhealthy"
                elif result["status"] == "degraded" and overall_status == "healthy":
                    overall_status = "degraded"

            except Exception as e:
                results[name] = {"status": "error", "message": str(e)}
                overall_status = "unhealthy"

        return {
            "status": overall_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "services": results,
        }

    def wait_all_healthy(self, interval: int = 2) -> bool:
        """
        Wait for all services to be healthy.

        Args:
            interval: Time between checks

        Returns:
            True if all services became healthy
        """
        logger.info("Waiting for all services to be healthy...")

        for name, checker in self.checkers.items():
            logger.info(f"Checking {name}...")
            if not checker.wait_until_healthy(interval):
                logger.error(f"Service {name} failed health check")
                return False

        logger.info("All services are healthy!")
        return True


def main() -> None:
    """Main entry point for health check script."""
    parser = argparse.ArgumentParser(description="Health check for Docker services")
    parser.add_argument(
        "service",
        choices=["postgresql", "redis", "api", "celery", "all"],
        help="Service to check",
    )
    parser.add_argument("--host", default="localhost", help="Service host")
    parser.add_argument("--port", type=int, help="Service port")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout in seconds")
    parser.add_argument("--wait", action="store_true", help="Wait until healthy")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    # Create appropriate health checker
    checker: HealthChecker
    if args.service == "postgresql":
        checker = PostgreSQLHealthChecker(host=args.host, port=args.port or 5432, timeout=args.timeout)
    elif args.service == "redis":
        checker = RedisHealthChecker(host=args.host, port=args.port or 6379, timeout=args.timeout)
    elif args.service == "api":
        base_url = f"http://{args.host}:{args.port or 8000}"
        checker = APIHealthChecker(base_url=base_url, timeout=args.timeout)
    elif args.service == "celery":
        broker_url = f"redis://{args.host}:{args.port or 6379}/1"
        checker = CeleryHealthChecker(broker_url=broker_url, timeout=args.timeout)
    elif args.service == "all":
        # Check all services
        checkers = {
            "postgresql": PostgreSQLHealthChecker(timeout=30),
            "redis": RedisHealthChecker(timeout=10),
            "api": APIHealthChecker(timeout=45),
            "celery": CeleryHealthChecker(timeout=30),
        }
        composite = CompositeHealthChecker(checkers)

        if args.wait:
            success = composite.wait_all_healthy()
            sys.exit(0 if success else 1)
        else:
            result = composite.check_all()
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"Overall status: {result['status']}")
                for service, status in result["services"].items():
                    print(f"  {service}: {status['status']} - {status.get('message', '')}")

            sys.exit(0 if result["status"] == "healthy" else 1)

    # Perform health check
    if args.wait:
        success = checker.wait_until_healthy()
        sys.exit(0 if success else 1)
    else:
        result = checker.check()

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"{result['service']}: {result['status']} - {result['message']}")

        sys.exit(0 if result["status"] == "healthy" else 1)


if __name__ == "__main__":
    main()
