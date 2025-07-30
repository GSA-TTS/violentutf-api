"""Performance and DoS resistance tests for security middleware.

This module tests the performance characteristics and DoS resistance
of the security middleware under various attack scenarios.
"""

import asyncio
import concurrent.futures
import json
import random
import string
import time
from statistics import mean, stdev
from typing import Dict, Generator, List, Tuple
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.csrf import CSRFProtectionMiddleware
from app.middleware.input_sanitization import InputSanitizationMiddleware
from app.utils.sanitization import (
    sanitize_ai_prompt,
    sanitize_dict,
    sanitize_html,
    sanitize_sql_input,
    sanitize_string,
    sanitize_url,
)


@pytest.fixture
def app():
    """Create test FastAPI app with security middleware."""
    app = FastAPI()

    # Add security middleware
    app.add_middleware(CSRFProtectionMiddleware)
    app.add_middleware(InputSanitizationMiddleware)

    @app.post("/api/process")
    async def process_endpoint(data: dict):
        return {"processed": data}

    @app.get("/api/search")
    async def search_endpoint(q: str = ""):
        return {"query": q}

    return app


@pytest.fixture
def client(app) -> Generator[TestClient, None, None]:
    """Create test client."""
    # Import TestClient locally to ensure correct resolution
    from fastapi.testclient import TestClient as FastAPITestClient

    with FastAPITestClient(app) as test_client:
        yield test_client


class TestSanitizationPerformance:
    """Test performance of sanitization functions."""

    def test_html_sanitization_performance(self):
        """Test HTML sanitization performance with various payloads."""
        test_cases = [
            # (name, payload_generator, iterations)
            ("small", lambda: "<p>Simple HTML</p>", 1000),
            ("medium", lambda: "<div>" + "<p>Paragraph</p>" * 100 + "</div>", 100),
            ("large", lambda: "<div>" + "<p>Large content</p>" * 1000 + "</div>", 10),
            ("nested", lambda: self._generate_nested_html(10), 100),
            ("malicious", lambda: self._generate_malicious_html(), 100),
        ]

        results = {}
        for name, generator, iterations in test_cases:
            times = []
            for _ in range(iterations):
                payload = generator()
                start = time.perf_counter()
                sanitize_html(payload)
                times.append(time.perf_counter() - start)

            results[name] = {
                "mean": mean(times),
                "stdev": stdev(times) if len(times) > 1 else 0,
                "max": max(times),
            }

        # Performance assertions
        assert results["small"]["mean"] < 0.001  # < 1ms for small
        assert results["medium"]["mean"] < 0.01  # < 10ms for medium
        assert results["large"]["mean"] < 0.1  # < 100ms for large

    def test_url_sanitization_performance(self):
        """Test URL sanitization performance."""
        urls = [
            "http://example.com/path",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "https://very.long.domain.name.example.com/very/long/path/to/resource?param=value",
        ] * 250  # 1000 URLs total

        start = time.perf_counter()
        for url in urls:
            sanitize_url(url)
        total_time = time.perf_counter() - start

        # Should process 1000 URLs in under 100ms
        assert total_time < 0.1
        assert (total_time / len(urls)) < 0.0001  # < 0.1ms per URL

    def test_sql_sanitization_performance(self):
        """Test SQL input sanitization performance."""
        inputs = [
            "normal input",
            "'; DROP TABLE users; --",
            "' OR 1=1 --",
            "very long input " * 100,
        ] * 250

        start = time.perf_counter()
        for inp in inputs:
            sanitize_sql_input(inp)
        total_time = time.perf_counter() - start

        assert total_time < 0.1  # < 100ms for 1000 inputs

    def test_ai_prompt_sanitization_performance(self):
        """Test AI prompt sanitization performance with large prompts."""
        # Generate prompts of various sizes
        prompts = []
        for size in [100, 1000, 10000, 50000]:
            prompt = " ".join(["word"] * (size // 5))
            prompts.append(prompt)

        times = []
        for prompt in prompts:
            start = time.perf_counter()
            sanitize_ai_prompt(prompt)
            times.append(time.perf_counter() - start)

        # Even 50K character prompts should process quickly
        assert max(times) < 0.1  # < 100ms

    def test_dict_sanitization_performance(self):
        """Test dictionary sanitization performance with nested structures."""

        # Create deeply nested dictionary
        def create_nested_dict(depth: int, width: int = 3) -> dict:
            if depth == 0:
                return {"value": "<script>alert(1)</script>"}
            return {f"key_{i}": create_nested_dict(depth - 1, width) for i in range(width)}

        test_dicts = [
            create_nested_dict(3),  # 3 levels deep
            create_nested_dict(5),  # 5 levels deep
            create_nested_dict(7),  # 7 levels deep
        ]

        for i, test_dict in enumerate(test_dicts):
            start = time.perf_counter()
            sanitize_dict(test_dict)
            elapsed = time.perf_counter() - start

            # Should handle nested structures efficiently
            assert elapsed < 0.1 * (i + 1)  # Scale with depth

    def _generate_nested_html(self, depth: int) -> str:
        """Generate nested HTML for testing."""
        if depth == 0:
            return "<p>Content</p>"
        return f"<div>{self._generate_nested_html(depth - 1)}</div>"

    def _generate_malicious_html(self) -> str:
        """Generate HTML with various attack vectors."""
        attacks = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            '<a href="javascript:alert(1)">link</a>',
            "<iframe src='javascript:alert(1)'></iframe>",
        ]
        return "<div>" + "".join(attacks * 10) + "</div>"


class TestMiddlewarePerformance:
    """Test middleware performance under load."""

    def test_csrf_token_generation_rate(self):
        """Test CSRF token generation rate."""
        middleware = CSRFProtectionMiddleware(None)

        start = time.perf_counter()
        tokens = [middleware._generate_csrf_token() for _ in range(10000)]
        elapsed = time.perf_counter() - start

        # Should generate 10K tokens quickly
        assert elapsed < 1.0  # < 1 second
        assert len(set(tokens)) == len(tokens)  # All unique

        # Calculate rate
        rate = len(tokens) / elapsed
        assert rate > 10000  # > 10K tokens per second

    def test_input_sanitization_middleware_latency(self, client):
        """Test latency added by input sanitization middleware."""
        payloads = [
            {"small": "data"},
            {"medium": "x" * 1000},
            {"large": "x" * 100000},
            {"nested": {"level1": {"level2": {"level3": "data"}}}},
            {"array": ["item"] * 100},
        ]

        latencies = []
        for payload in payloads:
            start = time.perf_counter()
            response = client.post("/api/process", json=payload)
            latency = time.perf_counter() - start
            latencies.append(latency)
            assert response.status_code == 200

        # Average latency should be reasonable
        assert mean(latencies) < 0.05  # < 50ms average
        assert max(latencies) < 0.1  # < 100ms max

    def test_concurrent_request_handling(self, client):
        """Test middleware performance under concurrent load."""

        def make_request(payload_size: int) -> float:
            payload = {"data": "x" * payload_size, "xss": "<script>alert(1)</script>"}
            start = time.perf_counter()
            response = client.post("/api/process", json=payload)
            elapsed = time.perf_counter() - start
            assert response.status_code in [200, 403]
            return elapsed

        # Test with thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # Submit 100 concurrent requests
            futures = []
            for i in range(100):
                payload_size = random.randint(100, 10000)
                futures.append(executor.submit(make_request, payload_size))

            # Collect results
            latencies = [f.result() for f in concurrent.futures.as_completed(futures)]

        # Performance assertions
        assert mean(latencies) < 0.1  # < 100ms average
        assert max(latencies) < 0.5  # < 500ms max
        successful = sum(1 for latency in latencies if latency < 0.1)
        assert successful > 90  # > 90% under 100ms


class TestDoSResistance:
    """Test resistance to Denial of Service attacks."""

    def test_large_payload_handling(self, client):
        """Test handling of very large payloads."""
        # Test payloads approaching and exceeding limits
        payload_sizes = [
            1_000_000,  # 1MB
            5_000_000,  # 5MB
            10_000_000,  # 10MB
            11_000_000,  # 11MB (over limit)
        ]

        for size in payload_sizes:
            payload = {"data": "x" * size}
            response = client.post("/api/process", json=payload)

            if size <= 10_000_000:
                assert response.status_code == 200
            else:
                assert response.status_code == 413  # Payload too large

    def test_algorithmic_complexity_attack(self, client):
        """Test resistance to algorithmic complexity attacks."""
        # Patterns designed to cause exponential processing
        complexity_patterns = [
            # Nested brackets that could cause backtracking
            "(" * 1000 + ")" * 1000,
            # Repeated patterns that might trigger O(n²) behavior
            ("a" * 100 + "b" * 100) * 50,
            # Many special characters requiring escaping
            "".join(random.choice("<>\"'&") for _ in range(10000)),
        ]

        for pattern in complexity_patterns:
            start = time.perf_counter()
            response = client.get(f"/api/search?q={pattern[:1000]}")  # Limit size
            elapsed = time.perf_counter() - start

            assert response.status_code == 200
            assert elapsed < 0.5  # Should not cause excessive delay

    def test_memory_exhaustion_resistance(self):
        """Test resistance to memory exhaustion attacks."""
        # Create payloads designed to consume memory
        memory_attacks = [
            # Very long strings without breaks
            "A" * 1_000_000,
            # Unicode that expands when processed
            "\u0041\u0301" * 100_000,  # A with combining accent
            # Deeply nested structures
            self._create_deep_nested_json(100),
        ]

        import os

        import psutil

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        for attack in memory_attacks:
            if isinstance(attack, str):
                sanitize_string(attack[:100_000])  # Limit size
            else:
                sanitize_dict(attack)

        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        # Memory increase should be reasonable
        assert memory_increase < 100_000_000  # < 100MB increase

    def test_cpu_exhaustion_resistance(self, client):
        """Test resistance to CPU exhaustion attacks."""
        # Patterns that could cause high CPU usage
        cpu_attacks = [
            # Regex-like patterns that might cause backtracking
            "a?" * 100 + "a" * 100,
            # Repeated escaping
            "&" * 10000,
            # Mixed encoding attacks
            "%3C%73%63%72%69%70%74%3E" * 1000,
        ]

        cpu_times = []
        for attack in cpu_attacks:
            start = time.process_time()
            response = client.get(f"/api/search?q={attack[:5000]}")
            cpu_time = time.process_time() - start
            cpu_times.append(cpu_time)
            assert response.status_code == 200

        # CPU time should be reasonable
        assert max(cpu_times) < 0.1  # < 100ms CPU time

    def test_connection_flood_resistance(self, client):
        """Test resistance to connection flooding."""
        # Simulate rapid connection attempts
        connection_times = []

        for _ in range(100):
            start = time.perf_counter()
            response = client.get("/api/search?q=test")
            elapsed = time.perf_counter() - start
            connection_times.append(elapsed)
            assert response.status_code == 200

        # Should handle rapid connections
        assert mean(connection_times) < 0.01  # < 10ms average
        assert max(connection_times) < 0.1  # < 100ms max

    def _create_deep_nested_json(self, depth: int) -> dict:
        """Create deeply nested JSON structure."""
        result = {"value": "end"}
        for _ in range(depth):
            result = {"nested": result}
        return result


class TestPerformanceOptimization:
    """Test performance optimization strategies."""

    def test_caching_effectiveness(self):
        """Test if caching improves performance for repeated operations."""
        # Same content sanitized multiple times
        content = "<p>Test content with <script>alert(1)</script></p>" * 100

        # First run (cold)
        cold_times = []
        for _ in range(10):
            start = time.perf_counter()
            sanitize_html(content)
            cold_times.append(time.perf_counter() - start)

        # Subsequent runs (might benefit from caching)
        warm_times = []
        for _ in range(10):
            start = time.perf_counter()
            sanitize_html(content)
            warm_times.append(time.perf_counter() - start)

        # Document performance characteristics
        cold_avg = mean(cold_times)
        warm_avg = mean(warm_times)

        # Both should be fast
        assert cold_avg < 0.01  # < 10ms
        assert warm_avg < 0.01  # < 10ms

    def test_batch_processing_performance(self):
        """Test performance when processing multiple items."""
        # Generate batch of items
        items = []
        for i in range(1000):
            items.append(
                {
                    "id": i,
                    "content": f"<p>Item {i} <script>alert({i})</script></p>",
                    "url": f"http://example.com/item/{i}",
                    "sql": f"SELECT * FROM items WHERE id = {i}",  # nosec B608 - test data
                }
            )

        # Process batch
        start = time.perf_counter()
        for item in items:
            sanitize_dict(item)
        batch_time = time.perf_counter() - start

        # Should process efficiently
        assert batch_time < 1.0  # < 1 second for 1000 items
        per_item_time = batch_time / len(items)
        assert per_item_time < 0.001  # < 1ms per item

    def test_parallel_processing_capability(self):
        """Test if parallel processing improves throughput."""
        import multiprocessing

        def process_batch(items: List[str]) -> float:
            start = time.perf_counter()
            for item in items:
                sanitize_html(item)
            return time.perf_counter() - start

        # Create work items
        work_items = [f"<p>Content {i}</p>" for i in range(10000)]

        # Sequential processing
        seq_time = process_batch(work_items)

        # Parallel processing
        num_processes = multiprocessing.cpu_count()
        chunk_size = len(work_items) // num_processes
        chunks = [work_items[i : i + chunk_size] for i in range(0, len(work_items), chunk_size)]

        with multiprocessing.Pool(processes=num_processes) as pool:
            start = time.perf_counter()
            pool.map(process_batch, chunks)
            par_time = time.perf_counter() - start

        # Parallel should be faster (or at least not much slower)
        # Note: Due to overhead, parallel might not always be faster for small tasks
        assert par_time < seq_time * 1.5


class TestResourceMonitoring:
    """Test resource usage monitoring during security operations."""

    def test_memory_usage_tracking(self):
        """Track memory usage during various operations."""
        import gc
        import os

        import psutil

        process = psutil.Process(os.getpid())

        operations = [
            ("HTML sanitization", lambda: sanitize_html("<p>Test</p>" * 1000)),
            ("Large dict sanitization", lambda: sanitize_dict({"key": "value"} for _ in range(1000))),
            ("AI prompt sanitization", lambda: sanitize_ai_prompt("prompt " * 10000)),
        ]

        memory_usage = {}
        for name, operation in operations:
            gc.collect()
            initial_memory = process.memory_info().rss

            # Run operation multiple times
            for _ in range(100):
                operation()

            gc.collect()
            final_memory = process.memory_info().rss
            memory_usage[name] = final_memory - initial_memory

        # Memory usage should be reasonable
        for name, usage in memory_usage.items():
            assert usage < 50_000_000  # < 50MB per operation type

    def test_cpu_usage_profiling(self):
        """Profile CPU usage for different security operations."""
        operations = [
            ("URL validation", lambda: [sanitize_url(f"http://example.com/{i}") for i in range(1000)]),
            (
                "SQL sanitization",
                lambda: [sanitize_sql_input(f"SELECT * FROM table_{i}") for i in range(1000)],  # nosec B608
            ),
            ("String sanitization", lambda: [sanitize_string(f"String {i} <script>") for i in range(1000)]),
        ]

        cpu_usage = {}
        for name, operation in operations:
            start_cpu = time.process_time()
            operation()
            cpu_usage[name] = time.process_time() - start_cpu

        # CPU usage should be reasonable
        for name, usage in cpu_usage.items():
            assert usage < 0.1  # < 100ms CPU time for 1000 operations
