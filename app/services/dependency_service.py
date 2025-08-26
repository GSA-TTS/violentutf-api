"""
Optimized dependency service for high-performance PyTestArch compliance testing.

This service provides bulk dependency analysis with caching, parallel processing,
and comprehensive performance optimization for architectural testing.

Implements ADR-015 performance optimization patterns and ADR-010 compliance.
"""

import asyncio
import json
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from structlog.stdlib import get_logger

from app.utils.dependency_cache import (
    DependencyCache,
    PackageInfo,
    get_dependency_cache,
)
from app.utils.performance_tracker import (
    PerformanceTracker,
    get_global_performance_tracker,
    track_performance,
)

logger = get_logger(__name__)


@dataclass
class VulnerabilityInfo:
    """Vulnerability information for a package."""

    package_name: str
    package_version: str
    vulnerability_id: str
    severity: str
    description: str
    fix_versions: List[str]


@dataclass
class LicenseInfo:
    """License information for a package."""

    package_name: str
    license_name: Optional[str]
    license_classifier: Optional[str]
    is_approved: bool
    is_restricted: bool
    is_prohibited: bool


@dataclass
class DependencyAnalysisResult:
    """Complete dependency analysis result."""

    total_packages: int
    analysis_duration: float
    cache_hit_rate: float
    approved_violations: List[Tuple[str, str, str]]
    license_violations: List[Tuple[str, str, str]]
    vulnerabilities: List[VulnerabilityInfo]
    outdated_packages: List[Tuple[str, str, int]]
    performance_metrics: Dict[str, Any]


class OptimizedDependencyService:
    """
    High-performance dependency analysis service with multi-level caching.

    Features:
    - Bulk package operations instead of individual calls
    - Multi-level caching (memory, file, optional Redis)
    - Parallel HTTP requests with rate limiting
    - Performance monitoring and metrics
    - Graceful degradation on failures
    """

    # Approved licenses from ADR-010
    APPROVED_LICENSES = {
        "MIT",
        "MIT License",
        "Apache-2.0",
        "Apache Software License",
        "BSD",
        "BSD-3-Clause",
        "BSD-2-Clause",
        "BSD License",
        "ISC",
        "Python Software Foundation License",
        "PSF",
        "Apache License 2.0",
        "Apache 2.0",
    }

    RESTRICTED_LICENSES = {
        "LGPL",
        "LGPL-2.1",
        "LGPL-3.0",
        "Lesser GPL",
    }

    PROHIBITED_LICENSES = {
        "GPL",
        "GPL-2.0",
        "GPL-3.0",
        "AGPL",
        "AGPL-3.0",
        "Commons Clause",
        "SSPL",
        "SSPL-1.0",
    }

    # Core approved packages from ADR-010
    APPROVED_PACKAGES = {
        # Web Framework
        "fastapi",
        "uvicorn",
        "gunicorn",
        "starlette",
        "httpx",
        # Database
        "sqlalchemy",
        "alembic",
        "asyncpg",
        "psycopg2",
        "psycopg2-binary",
        "aiosqlite",
        "databases",
        # Security
        "passlib",
        "python-jose",
        "cryptography",
        "bcrypt",
        "argon2-cffi",
        "python-multipart",
        "pyjwt",
        # Validation
        "pydantic",
        "email-validator",
        "python-dateutil",
        # Redis/Caching
        "redis",
        "aioredis",
        "hiredis",
        # Celery/Tasks
        "celery",
        "kombu",
        "amqp",
        "billiard",
        "vine",
        # Testing
        "pytest",
        "pytest-asyncio",
        "pytest-cov",
        "pytest-mock",
        "pytest-benchmark",
        "pytest-xdist",
        "faker",
        "polyfactory",
        "hypothesis",
        "pytest-timeout",
        "pytest-env",
        "pytest-httpx",
        # Development Tools
        "black",
        "isort",
        "flake8",
        "mypy",
        "ruff",
        "bandit",
        "pip-audit",
        "semgrep",
        "pre-commit",
        "pydriller",
        "lizard",
        # Documentation
        "mkdocs",
        "mkdocs-material",
        # Utilities
        "python-dotenv",
        "pyyaml",
        "click",
        "rich",
        "tenacity",
        "structlog",
        "loguru",
        "prometheus-client",
        "psutil",
        # Type stubs
        "types-requests",
        "types-redis",
        "types-passlib",
        "types-bleach",
        "types-psutil",
        "types-pyyaml",
        # Monitoring
        "opentelemetry-api",
        "opentelemetry-sdk",
        "opentelemetry-instrumentation",
        # AI/ML (for ViolentUTF specific)
        "pyrit",
        "garak",
        "ollama",
        "langchain",
        "openai",
        # Architecture testing
        "pytestarch",
        "networkx",
    }

    # Known acceptable sub-dependencies
    APPROVED_SUBDEPENDENCIES = {
        # FastAPI ecosystem
        "anyio",
        "sniffio",
        "h11",
        "httpcore",
        "httptools",
        "python-dotenv",
        "watchfiles",
        "websockets",
        "uvloop",
        # SQLAlchemy ecosystem
        "greenlet",
        "mako",
        "markupsafe",
        "typing-extensions",
        # Celery ecosystem
        "click-didyoumean",
        "click-plugins",
        "click-repl",
        "flower",
        "tornado",
        "prometheus-client",
        # Pydantic ecosystem
        "annotated-types",
        "pydantic-core",
        # Testing ecosystem
        "iniconfig",
        "pluggy",
        "py",
        "toml",
        "tomli",
        "attrs",
        "coverage",
        "execnet",
        "pytest-runner",
    }

    def __init__(
        self,
        cache: Optional[DependencyCache] = None,
        max_concurrent_requests: int = 10,
        request_timeout: float = 10.0,
        performance_tracker: Optional[PerformanceTracker] = None,
    ):
        self.cache = cache or get_dependency_cache()
        self.max_concurrent_requests = max_concurrent_requests
        self.request_timeout = request_timeout
        self.performance_tracker = performance_tracker or get_global_performance_tracker()

        # HTTP client for PyPI requests
        self._http_client: Optional[httpx.AsyncClient] = None
        self._semaphore = asyncio.Semaphore(max_concurrent_requests)

        # Thread pool for subprocess operations
        self._thread_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dep-service")

        # Circuit breaker for external API failures
        self._circuit_breaker = {
            "failures": 0,
            "last_failure": 0,
            "threshold": 5,
            "reset_timeout": 300,  # 5 minutes
        }

    async def __aenter__(self):
        """Async context manager entry."""
        await self._ensure_http_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def _ensure_http_client(self):
        """Ensure HTTP client is initialized."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.request_timeout),
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
                follow_redirects=True,
            )

    async def close(self):
        """Close resources."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

        # Shutdown thread pool in a non-blocking way
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._thread_pool.shutdown, True)

    def _is_circuit_breaker_open(self) -> bool:
        """Check if circuit breaker is open."""
        if self._circuit_breaker["failures"] >= self._circuit_breaker["threshold"]:
            if time.time() - self._circuit_breaker["last_failure"] > self._circuit_breaker["reset_timeout"]:
                # Reset circuit breaker
                self._circuit_breaker["failures"] = 0
                logger.info("Circuit breaker reset")
                return False
            return True
        return False

    def _record_circuit_breaker_failure(self):
        """Record a circuit breaker failure."""
        self._circuit_breaker["failures"] += 1
        self._circuit_breaker["last_failure"] = time.time()
        logger.warning(
            "Circuit breaker failure recorded",
            failures=self._circuit_breaker["failures"],
        )

    @track_performance("get_installed_packages_bulk")
    async def get_installed_packages_bulk(self) -> Dict[str, str]:
        """
        Get all installed packages in a single efficient call.

        Returns:
            Dictionary mapping package names to versions
        """

        def _run_pip_list() -> Dict[str, str]:
            """Run pip list in thread pool."""
            try:
                result = subprocess.run(
                    ["pip", "list", "--format=json"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )

                packages_data = json.loads(result.stdout)
                return {pkg["name"].lower(): pkg["version"] for pkg in packages_data}

            except (
                subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                json.JSONDecodeError,
            ) as e:
                logger.error("Failed to get installed packages", error=str(e))
                raise

        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        packages = await loop.run_in_executor(self._thread_pool, _run_pip_list)

        logger.info("Retrieved installed packages", count=len(packages))
        return packages

    @track_performance("fetch_package_metadata")
    async def _fetch_package_metadata_from_pypi(self, package_name: str) -> Optional[dict]:
        """
        Fetch package metadata from PyPI with circuit breaker protection.

        Args:
            package_name: Name of package to fetch metadata for

        Returns:
            Package metadata dictionary or None if failed
        """
        if self._is_circuit_breaker_open():
            logger.warning("Circuit breaker open, skipping PyPI request", package=package_name)
            return None

        await self._ensure_http_client()

        async with self._semaphore:
            try:
                url = f"https://pypi.org/pypi/{package_name}/json"
                response = await self._http_client.get(url)
                response.raise_for_status()

                data = response.json()
                logger.debug("Fetched package metadata from PyPI", package=package_name)
                return data

            except httpx.RequestError as e:
                self._record_circuit_breaker_failure()
                logger.warning(
                    "Failed to fetch package metadata",
                    package=package_name,
                    error=str(e),
                )
                return None
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.debug("Package not found on PyPI", package=package_name)
                else:
                    self._record_circuit_breaker_failure()
                    logger.warning(
                        "HTTP error fetching package metadata",
                        package=package_name,
                        status_code=e.response.status_code,
                    )
                return None

    @track_performance("get_bulk_package_metadata")
    async def get_bulk_package_metadata(self, package_names: List[str]) -> Dict[str, PackageInfo]:
        """
        Get metadata for multiple packages efficiently with caching.

        Args:
            package_names: List of package names to get metadata for

        Returns:
            Dictionary mapping package names to PackageInfo objects
        """
        results = {}

        # First, try to get from cache in bulk
        cached_results = await self.cache.bulk_get_package_info(package_names)
        results.update(cached_results)

        # Identify packages not in cache
        missing_packages = [pkg for pkg in package_names if pkg not in results]

        if not missing_packages:
            logger.info(
                "All package metadata retrieved from cache",
                total=len(package_names),
                cached=len(results),
            )
            return results

        logger.info(
            "Fetching missing package metadata from PyPI",
            total=len(package_names),
            cached=len(results),
            missing=len(missing_packages),
        )

        # Fetch missing packages in parallel
        async def fetch_and_cache_package(
            package_name: str,
        ) -> Tuple[str, Optional[PackageInfo]]:
            """Fetch package metadata and cache it."""
            metadata = await self._fetch_package_metadata_from_pypi(package_name)

            if metadata:
                # Extract relevant information
                info = metadata.get("info", {})
                pkg_info = PackageInfo(
                    name=package_name,
                    version=info.get("version", "unknown"),
                    license=info.get("license"),
                    summary=info.get("summary"),
                    home_page=info.get("home_page"),
                    author=info.get("author"),
                    requires=info.get("requires_dist", []) or [],
                    last_updated=metadata.get("last_serial"),
                )

                # Cache the result
                await self.cache.set_package_info(package_name, pkg_info)
                return package_name, pkg_info

            return package_name, None

        # Execute parallel fetches
        tasks = [fetch_and_cache_package(pkg) for pkg in missing_packages]
        fetch_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in fetch_results:
            if isinstance(result, Exception):
                logger.error("Error fetching package metadata", error=str(result))
                continue

            if isinstance(result, tuple) and len(result) == 2:
                package_name, pkg_info = result
                if pkg_info:
                    results[package_name] = pkg_info

        logger.info(
            "Bulk package metadata retrieval completed",
            total_requested=len(package_names),
            from_cache=len(cached_results),
            from_api=len(results) - len(cached_results),
        )

        return results

    async def validate_approved_dependencies(self, installed_packages: Dict[str, str]) -> List[Tuple[str, str, str]]:
        """
        Validate that all dependencies are approved per ADR-010.

        Args:
            installed_packages: Dictionary of package names to versions

        Returns:
            List of (package, version, issue) tuples for violations
        """
        violations = []

        # Skip standard library and build packages
        skip_patterns = [
            r"^_",
            r"^pip$",
            r"^setuptools$",
            r"^wheel$",
            r"^certifi$",
            r"^charset-normalizer$",
            r"^idna$",
            r"^urllib3$",
            r"^six$",
            r"^packaging$",
        ]

        with self.performance_tracker.track_operation("validate_approved_dependencies"):
            for package_name, version in installed_packages.items():
                # Skip if matches skip pattern
                if any(re.match(pattern, package_name) for pattern in skip_patterns):
                    continue

                # Remove extras specification
                base_package = package_name.split("[")[0]

                # Check if package is explicitly approved
                if base_package not in self.APPROVED_PACKAGES:
                    # Check if it's an approved sub-dependency
                    if base_package.lower() not in self.APPROVED_SUBDEPENDENCIES:
                        violations.append((package_name, version, "Not in approved packages list"))

        return violations

    async def check_license_compliance(self, package_metadata: Dict[str, PackageInfo]) -> List[LicenseInfo]:
        """
        Check license compliance for packages.

        Args:
            package_metadata: Dictionary of package metadata

        Returns:
            List of LicenseInfo objects with compliance status
        """
        license_results = []

        with self.performance_tracker.track_operation("check_license_compliance"):
            for package_name, pkg_info in package_metadata.items():
                license_name = pkg_info.license or "Unknown"

                # Classify license
                is_prohibited = any(
                    prohibited.lower() in license_name.lower() for prohibited in self.PROHIBITED_LICENSES
                )
                is_restricted = any(
                    restricted.lower() in license_name.lower() for restricted in self.RESTRICTED_LICENSES
                )
                is_approved = any(approved.lower() in license_name.lower() for approved in self.APPROVED_LICENSES)

                license_info = LicenseInfo(
                    package_name=package_name,
                    license_name=license_name,
                    license_classifier=None,  # Could be enhanced to parse classifiers
                    is_approved=is_approved and not is_restricted and not is_prohibited,
                    is_restricted=is_restricted,
                    is_prohibited=is_prohibited,
                )

                license_results.append(license_info)

        return license_results

    @track_performance("check_vulnerabilities")
    async def check_vulnerabilities(self, installed_packages: Dict[str, str]) -> List[VulnerabilityInfo]:
        """
        Check for vulnerabilities using pip-audit.

        Args:
            installed_packages: Dictionary of installed packages

        Returns:
            List of VulnerabilityInfo objects
        """
        vulnerabilities = []

        def _run_pip_audit() -> List[VulnerabilityInfo]:
            """Run pip-audit in thread pool."""
            try:
                result = subprocess.run(
                    ["pip-audit", "--format", "json", "--desc"],
                    capture_output=True,
                    text=True,
                    check=False,  # Don't raise on non-zero exit (vulnerabilities found)
                    timeout=60,
                )

                if result.stdout:
                    audit_data = json.loads(result.stdout)
                    vulns = []

                    for vuln in audit_data.get("vulnerabilities", []):
                        vulns.append(
                            VulnerabilityInfo(
                                package_name=vuln.get("name", "unknown"),
                                package_version=vuln.get("version", "unknown"),
                                vulnerability_id=vuln.get("id", "unknown"),
                                severity=vuln.get("severity", "unknown"),
                                description=vuln.get("description", ""),
                                fix_versions=vuln.get("fix_versions", []),
                            )
                        )

                    return vulns

                return []

            except (
                subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                json.JSONDecodeError,
                FileNotFoundError,
            ) as e:
                logger.warning("pip-audit failed", error=str(e))
                return []

        # Run pip-audit in thread pool
        loop = asyncio.get_event_loop()
        vulnerabilities = await loop.run_in_executor(self._thread_pool, _run_pip_audit)

        return vulnerabilities

    @track_performance("full_dependency_analysis")
    async def analyze_dependencies(self, reset_cache_stats: bool = False) -> DependencyAnalysisResult:
        """
        Perform complete dependency analysis with performance optimization.

        Args:
            reset_cache_stats: If True, reset cache statistics for clean measurement

        Returns:
            Complete analysis result with performance metrics
        """
        if reset_cache_stats:
            self.cache.reset_cache_stats()

        start_time = time.time()

        async with self.performance_tracker.track_async_operation("full_dependency_analysis") as op_id:
            # Step 1: Get all installed packages (bulk operation)
            installed_packages = await self.get_installed_packages_bulk()

            # Step 2: Get package metadata (bulk with caching)
            package_metadata = await self.get_bulk_package_metadata(list(installed_packages.keys()))

            # Step 3: Validate approved dependencies
            approved_violations = await self.validate_approved_dependencies(installed_packages)

            # Step 4: Check license compliance
            license_info = await self.check_license_compliance(package_metadata)
            license_violations = []
            for info in license_info:
                if info.is_prohibited:
                    license_violations.append(
                        (
                            info.package_name,
                            info.license_name,
                            f"Prohibited license: {info.license_name}",
                        )
                    )
                elif info.is_restricted:
                    license_violations.append(
                        (
                            info.package_name,
                            info.license_name,
                            f"Restricted license: {info.license_name}",
                        )
                    )

            # Step 5: Check vulnerabilities (in parallel if possible)
            vulnerabilities = await self.check_vulnerabilities(installed_packages)

            # Calculate performance metrics
            analysis_duration = time.time() - start_time
            cache_stats = self.cache.get_cache_stats()
            cache_hit_rate = cache_stats.hit_rate

            # Update performance tracker with memory usage
            self.performance_tracker.update_operation_memory(op_id)

        # Generate performance report
        performance_report = self.performance_tracker.get_performance_report()

        return DependencyAnalysisResult(
            total_packages=len(installed_packages),
            analysis_duration=analysis_duration,
            cache_hit_rate=cache_hit_rate,
            approved_violations=approved_violations,
            license_violations=license_violations,
            vulnerabilities=vulnerabilities,
            outdated_packages=[],  # Could be implemented if needed
            performance_metrics=performance_report,
        )

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform service health check.

        Returns:
            Health check results
        """
        health = {
            "service": "dependency_service",
            "status": "healthy",
            "timestamp": time.time(),
        }

        try:
            # Test cache
            cache_health = await self.cache.health_check()
            health["cache"] = cache_health

            # Test HTTP client
            await self._ensure_http_client()
            health["http_client"] = {
                "initialized": self._http_client is not None,
                "max_connections": self.max_concurrent_requests,
            }

            # Circuit breaker status
            health["circuit_breaker"] = {
                "open": self._is_circuit_breaker_open(),
                "failures": self._circuit_breaker["failures"],
                "threshold": self._circuit_breaker["threshold"],
            }

            # Performance tracker status
            health["performance_tracker"] = {
                "operations_tracked": len(self.performance_tracker._history),
                "total_executions": sum(len(h) for h in self.performance_tracker._history.values()),
            }

        except Exception as e:
            health["status"] = "unhealthy"
            health["error"] = str(e)

        return health


# Factory function for service creation
async def create_dependency_service(
    cache_dir: Optional[Path] = None,
    max_concurrent_requests: int = 10,
    cache_ttl: int = 86400,
) -> OptimizedDependencyService:
    """
    Factory function to create optimized dependency service.

    Args:
        cache_dir: Directory for file cache
        max_concurrent_requests: Maximum concurrent HTTP requests
        cache_ttl: Cache TTL in seconds

    Returns:
        Configured OptimizedDependencyService instance
    """
    cache = get_dependency_cache(cache_dir=cache_dir, ttl=cache_ttl)
    service = OptimizedDependencyService(cache=cache, max_concurrent_requests=max_concurrent_requests)

    await service._ensure_http_client()
    return service
