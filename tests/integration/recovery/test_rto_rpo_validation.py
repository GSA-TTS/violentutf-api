"""Integration tests for RTO/RPO validation and measurement."""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from scripts.rto_rpo_validator import (
    RecoveryMetrics,
    RecoveryScenario,
    RTORPOValidator,
    ServiceTier,
    ValidationResult,
)


class TestRTORPOValidation:
    """Integration tests for RTO/RPO validation framework."""

    @pytest.fixture
    def validator(self):
        """Create RTO/RPO validator instance."""
        return RTORPOValidator()

    @pytest.fixture
    def critical_service_config(self):
        """Configuration for critical service tier."""
        return {
            "tier": ServiceTier.CRITICAL,
            "rto_target_minutes": 15,
            "rpo_target_minutes": 60,
            "services": ["violentutf-api", "violentutf-db"],
        }

    @pytest.fixture
    def standard_service_config(self):
        """Configuration for standard service tier."""
        return {
            "tier": ServiceTier.STANDARD,
            "rto_target_minutes": 30,
            "rpo_target_minutes": 240,
            "services": ["violentutf-redis", "violentutf-celery"],
        }

    @pytest.mark.asyncio
    async def test_full_system_recovery_rto_critical(self, validator, critical_service_config):
        """Test full system recovery meets critical RTO requirements."""
        # Simulate full system disaster recovery
        recovery_scenario = RecoveryScenario(
            name="full_system_disaster_recovery",
            description="Complete system failure requiring full restoration",
            service_tier=ServiceTier.CRITICAL,
            failure_type="total_system_failure",
            data_loss_window_minutes=30,
        )

        start_time = time.time()

        # Mock the recovery process
        with (
            patch("scripts.rto_rpo_validator.DockerComposeManager") as mock_docker,
            patch("scripts.rto_rpo_validator.DatabaseRecoveryManager") as mock_db,
        ):

            # Mock successful recovery steps
            mock_docker.return_value.stop_all_services.return_value = True
            mock_docker.return_value.restore_from_backup.return_value = True
            mock_docker.return_value.start_all_services.return_value = True
            mock_db.return_value.restore_database.return_value = True

            # Execute recovery test
            result = await validator.execute_recovery_test(recovery_scenario)

            recovery_time_minutes = (time.time() - start_time) / 60

            # Validate RTO compliance
            assert result.success is True
            assert recovery_time_minutes < critical_service_config["rto_target_minutes"]
            assert result.actual_rto_minutes <= critical_service_config["rto_target_minutes"]

    @pytest.mark.asyncio
    async def test_database_recovery_rpo_validation(self, validator, critical_service_config):
        """Test database recovery meets RPO requirements."""
        # Create test scenario with known data loss window
        recovery_scenario = RecoveryScenario(
            name="database_corruption_recovery",
            description="Database corruption requiring restore from backup",
            service_tier=ServiceTier.CRITICAL,
            failure_type="database_corruption",
            failure_time=datetime.now() - timedelta(minutes=45),
            last_backup_time=datetime.now() - timedelta(minutes=50),
        )

        with patch("scripts.rto_rpo_validator.PostgresBackupManager") as mock_postgres:
            # Mock backup information
            mock_postgres.return_value.get_latest_backup_info.return_value = {
                "backup_time": recovery_scenario.last_backup_time,
                "backup_type": "full",
                "integrity_verified": True,
            }

            result = await validator.execute_recovery_test(recovery_scenario)

            # Calculate actual RPO
            actual_rpo_minutes = (
                recovery_scenario.failure_time - recovery_scenario.last_backup_time
            ).total_seconds() / 60

            # Validate RPO compliance
            assert result.success is True
            assert actual_rpo_minutes <= critical_service_config["rpo_target_minutes"]
            assert result.actual_rpo_minutes <= critical_service_config["rpo_target_minutes"]

    @pytest.mark.asyncio
    async def test_point_in_time_recovery_precision(self, validator):
        """Test point-in-time recovery precision and RPO validation."""
        target_recovery_time = datetime.now() - timedelta(hours=2)

        recovery_scenario = RecoveryScenario(
            name="point_in_time_recovery",
            description="Restore database to specific point in time",
            service_tier=ServiceTier.CRITICAL,
            failure_type="data_corruption",
            target_recovery_time=target_recovery_time,
        )

        with patch("scripts.rto_rpo_validator.PostgresBackupManager") as mock_postgres:
            # Mock point-in-time recovery capability
            mock_postgres.return_value.restore_to_point_in_time.return_value = {
                "success": True,
                "actual_recovery_time": target_recovery_time + timedelta(seconds=30),
                "precision_seconds": 30,
            }

            result = await validator.execute_recovery_test(recovery_scenario)

            # Validate precision (should be within 5 minutes of target)
            assert result.success is True
            assert result.recovery_precision_seconds <= 300  # 5 minutes

    @pytest.mark.asyncio
    async def test_partial_service_recovery_rto(self, validator, standard_service_config):
        """Test partial service recovery meets RTO requirements."""
        recovery_scenario = RecoveryScenario(
            name="redis_service_failure",
            description="Redis service failure requiring restart and data recovery",
            service_tier=ServiceTier.STANDARD,
            failure_type="service_failure",
            affected_services=["violentutf-redis"],
        )

        start_time = time.time()

        with (
            patch("scripts.rto_rpo_validator.RedisBackupManager") as mock_redis,
            patch("scripts.rto_rpo_validator.DockerComposeManager") as mock_docker,
        ):

            # Mock Redis recovery
            mock_redis.return_value.restore_from_backup.return_value = True
            mock_docker.return_value.restart_service.return_value = True

            result = await validator.execute_recovery_test(recovery_scenario)

            recovery_time_minutes = (time.time() - start_time) / 60

            # Standard tier has more relaxed RTO requirements
            assert result.success is True
            assert recovery_time_minutes < standard_service_config["rto_target_minutes"]

    @pytest.mark.asyncio
    async def test_concurrent_recovery_operations(self, validator):
        """Test concurrent recovery operations don't exceed resource limits."""
        # Create multiple recovery scenarios
        scenarios = [
            RecoveryScenario(
                name=f"concurrent_recovery_{i}",
                description=f"Concurrent recovery test {i}",
                service_tier=ServiceTier.STANDARD,
                failure_type="service_failure",
            )
            for i in range(3)
        ]

        start_time = time.time()

        # Execute concurrent recoveries
        with patch("scripts.rto_rpo_validator.ResourceMonitor") as mock_monitor:
            mock_monitor.return_value.get_current_usage.return_value = {
                "cpu_percent": 45,
                "memory_percent": 60,
                "disk_io_percent": 30,
            }

            results = await asyncio.gather(*[validator.execute_recovery_test(scenario) for scenario in scenarios])

            total_time_minutes = (time.time() - start_time) / 60

            # All recoveries should succeed
            assert all(result.success for result in results)

            # Resource usage should stay within limits
            assert mock_monitor.return_value.get_current_usage.call_count > 0

    @pytest.mark.asyncio
    async def test_recovery_validation_with_health_checks(self, validator):
        """Test recovery validation includes comprehensive health checks."""
        recovery_scenario = RecoveryScenario(
            name="recovery_with_validation",
            description="Recovery with comprehensive post-recovery validation",
            service_tier=ServiceTier.CRITICAL,
            failure_type="system_failure",
        )

        with patch("scripts.rto_rpo_validator.HealthCheckManager") as mock_health:
            # Mock health check progression
            mock_health.return_value.check_all_services.side_effect = [
                {"overall_status": "starting", "healthy_services": 0, "total_services": 4},
                {"overall_status": "partial", "healthy_services": 2, "total_services": 4},
                {"overall_status": "healthy", "healthy_services": 4, "total_services": 4},
            ]

            result = await validator.execute_recovery_test(recovery_scenario)

            # Recovery should include health validation
            assert result.success is True
            assert result.health_checks_passed is True
            assert mock_health.return_value.check_all_services.call_count >= 3

    @pytest.mark.asyncio
    async def test_data_consistency_validation_post_recovery(self, validator):
        """Test data consistency validation after recovery."""
        recovery_scenario = RecoveryScenario(
            name="recovery_with_data_validation",
            description="Recovery with data consistency validation",
            service_tier=ServiceTier.CRITICAL,
            failure_type="data_corruption",
        )

        with patch("scripts.rto_rpo_validator.DataConsistencyValidator") as mock_validator:
            # Mock data consistency checks
            mock_validator.return_value.validate_all_repositories.return_value = {
                "consistent": True,
                "validation_results": {
                    "user_repository": {"status": "valid", "record_count": 1000},
                    "audit_log_repository": {"status": "valid", "record_count": 5000},
                },
                "inconsistencies": [],
            }

            result = await validator.execute_recovery_test(recovery_scenario)

            assert result.success is True
            assert result.data_consistency_validated is True
            assert len(result.data_inconsistencies) == 0

    def test_rto_measurement_accuracy(self, validator):
        """Test RTO measurement accuracy and precision."""
        # Create controlled timing scenario
        start_time = datetime.now()

        # Simulate recovery steps with known durations
        recovery_steps = [
            {"name": "stop_services", "duration_seconds": 30},
            {"name": "restore_database", "duration_seconds": 480},  # 8 minutes
            {"name": "start_services", "duration_seconds": 120},  # 2 minutes
            {"name": "validate_health", "duration_seconds": 60},  # 1 minute
        ]

        metrics = validator.measure_recovery_metrics(start_time, recovery_steps)

        expected_total_seconds = sum(step["duration_seconds"] for step in recovery_steps)
        expected_total_minutes = expected_total_seconds / 60

        # Allow small tolerance for measurement precision
        assert abs(metrics.total_rto_minutes - expected_total_minutes) < 0.1
        assert len(metrics.step_durations) == len(recovery_steps)

    def test_rpo_calculation_with_incremental_backups(self, validator):
        """Test RPO calculation with incremental backup scenarios."""
        # Scenario with incremental backups
        failure_time = datetime.now()
        last_full_backup = failure_time - timedelta(hours=24)
        last_incremental_backup = failure_time - timedelta(minutes=45)

        rpo_metrics = validator.calculate_rpo_metrics(
            failure_time=failure_time,
            last_full_backup=last_full_backup,
            last_incremental_backup=last_incremental_backup,
            incremental_frequency_minutes=60,
        )

        # RPO should be based on last incremental backup
        expected_rpo_minutes = 45
        assert abs(rpo_metrics.actual_rpo_minutes - expected_rpo_minutes) < 1

    def test_recovery_scenario_classification(self, validator):
        """Test recovery scenario classification and prioritization."""
        scenarios = [
            RecoveryScenario(
                name="critical_database_failure",
                service_tier=ServiceTier.CRITICAL,
                failure_type="database_failure",
                data_loss_severity="high",
            ),
            RecoveryScenario(
                name="standard_service_restart",
                service_tier=ServiceTier.STANDARD,
                failure_type="service_failure",
                data_loss_severity="none",
            ),
            RecoveryScenario(
                name="important_cache_failure",
                service_tier=ServiceTier.IMPORTANT,
                failure_type="cache_failure",
                data_loss_severity="low",
            ),
        ]

        prioritized_scenarios = validator.prioritize_recovery_scenarios(scenarios)

        # Critical scenarios should be first
        assert prioritized_scenarios[0].service_tier == ServiceTier.CRITICAL
        assert prioritized_scenarios[0].priority_score > prioritized_scenarios[1].priority_score

    @pytest.mark.asyncio
    async def test_automated_recovery_test_scheduling(self, validator):
        """Test automated recovery test scheduling and execution."""
        # Configure monthly recovery test schedule
        schedule_config = {
            "frequency": "monthly",
            "day_of_month": 15,
            "time": "02:00",
            "scenarios": ["full_system_recovery", "database_recovery"],
        }

        with patch("scripts.rto_rpo_validator.CronScheduler") as mock_scheduler:
            validator.configure_automated_testing(schedule_config)

            # Verify scheduling was configured
            assert mock_scheduler.return_value.add_job.called

            # Verify test scenarios are available
            scheduled_scenarios = validator.get_scheduled_scenarios()
            assert len(scheduled_scenarios) >= 2

    def test_recovery_metrics_aggregation(self, validator):
        """Test recovery metrics aggregation and reporting."""
        # Create sample recovery test results
        test_results = [
            ValidationResult(
                scenario_name="test_1",
                success=True,
                actual_rto_minutes=12,
                actual_rpo_minutes=45,
                service_tier=ServiceTier.CRITICAL,
            ),
            ValidationResult(
                scenario_name="test_2",
                success=True,
                actual_rto_minutes=18,
                actual_rpo_minutes=30,
                service_tier=ServiceTier.CRITICAL,
            ),
            ValidationResult(
                scenario_name="test_3",
                success=False,
                actual_rto_minutes=25,
                actual_rpo_minutes=90,
                service_tier=ServiceTier.CRITICAL,
            ),
        ]

        aggregated_metrics = validator.aggregate_recovery_metrics(test_results)

        assert aggregated_metrics["average_rto_minutes"] == 18.33
        assert aggregated_metrics["average_rpo_minutes"] == 55.0
        assert aggregated_metrics["success_rate"] == 66.67
        assert aggregated_metrics["rto_compliance_rate"] == 66.67  # 2 out of 3 under 15 min

    def test_performance_impact_during_recovery(self, validator):
        """Test performance impact measurement during recovery operations."""
        recovery_scenario = RecoveryScenario(
            name="performance_impact_test",
            description="Measure performance impact during recovery",
            service_tier=ServiceTier.CRITICAL,
            failure_type="planned_maintenance",
        )

        with patch("scripts.rto_rpo_validator.PerformanceMonitor") as mock_perf:
            # Mock performance measurements
            mock_perf.return_value.get_baseline_metrics.return_value = {
                "response_time_ms": 100,
                "throughput_rps": 1000,
                "error_rate_percent": 0.1,
            }

            mock_perf.return_value.get_current_metrics.return_value = {
                "response_time_ms": 150,
                "throughput_rps": 800,
                "error_rate_percent": 0.5,
            }

            impact_metrics = validator.measure_performance_impact(recovery_scenario)

            assert impact_metrics["response_time_degradation_percent"] == 50
            assert impact_metrics["throughput_degradation_percent"] == 20
            assert impact_metrics["error_rate_increase"] == 0.4


class TestRecoveryMetrics:
    """Test recovery metrics data structures."""

    def test_recovery_metrics_creation(self):
        """Test recovery metrics object creation."""
        metrics = RecoveryMetrics(
            total_rto_minutes=15.5,
            actual_rpo_minutes=45.0,
            step_durations=[30, 480, 120, 60],
            data_consistency_score=98.5,
        )

        assert metrics.total_rto_minutes == 15.5
        assert metrics.actual_rpo_minutes == 45.0
        assert len(metrics.step_durations) == 4

    def test_recovery_metrics_compliance_check(self):
        """Test recovery metrics compliance validation."""
        # Compliant metrics
        compliant_metrics = RecoveryMetrics(
            total_rto_minutes=12.0,
            actual_rpo_minutes=45.0,
        )

        assert compliant_metrics.is_rto_compliant(15.0) is True
        assert compliant_metrics.is_rpo_compliant(60.0) is True

        # Non-compliant metrics
        non_compliant_metrics = RecoveryMetrics(
            total_rto_minutes=20.0,
            actual_rpo_minutes=90.0,
        )

        assert non_compliant_metrics.is_rto_compliant(15.0) is False
        assert non_compliant_metrics.is_rpo_compliant(60.0) is False


if __name__ == "__main__":
    pytest.main([__file__])
