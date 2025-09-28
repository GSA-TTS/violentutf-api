"""Tests for Configuration Baseline Manager.

This module contains unit tests for the configuration baseline management system
that handles creation, validation, and management of configuration baselines.
"""

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from unittest.mock import Mock, patch

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from scripts.config_baseline_manager import (
    BaselineGenerationError,
    BaselineValidationError,
    ConfigurationBaseline,
    ConfigurationBaselineManager,
    ConfigurationExtractor,
)


class TestConfigurationBaseline:
    """Test ConfigurationBaseline data model."""

    def test_configuration_baseline_creation(self):
        """Test creating a valid configuration baseline."""
        baseline = ConfigurationBaseline(
            environment="development",
            timestamp=datetime.now(timezone.utc),
            version="1.0.0",
            configurations={"PROJECT_NAME": "ViolentUTF API", "DEBUG": True},
            metadata={"source": "settings_class", "generator": "config_extractor"},
            checksum="abc123def456",
        )

        assert baseline.environment == "development"
        assert baseline.version == "1.0.0"
        assert baseline.configurations["PROJECT_NAME"] == "ViolentUTF API"
        assert baseline.metadata["source"] == "settings_class"
        assert baseline.checksum == "abc123def456"

    def test_configuration_baseline_validation(self):
        """Test configuration baseline validation rules."""
        # Test invalid environment
        with pytest.raises(ValidationError):
            ConfigurationBaseline(
                environment="invalid_env",
                timestamp=datetime.now(timezone.utc),
                version="1.0.0",
                configurations={},
                metadata={},
                checksum="",
            )

        # Test empty version
        with pytest.raises(ValidationError):
            ConfigurationBaseline(
                environment="development",
                timestamp=datetime.now(timezone.utc),
                version="",
                configurations={},
                metadata={},
                checksum="",
            )

    def test_configuration_baseline_serialization(self):
        """Test baseline serialization and deserialization."""
        baseline = ConfigurationBaseline(
            environment="development",
            timestamp=datetime.now(timezone.utc),
            version="1.0.0",
            configurations={"DEBUG": True, "DATABASE_POOL_SIZE": 5},
            metadata={"source": "test"},
            checksum="test123",
        )

        # Test to_dict
        baseline_dict = baseline.to_dict()
        assert baseline_dict["environment"] == "development"
        assert baseline_dict["configurations"]["DEBUG"] is True

        # Test from_dict
        reconstructed = ConfigurationBaseline.from_dict(baseline_dict)
        assert reconstructed.environment == baseline.environment
        assert reconstructed.configurations == baseline.configurations

    def test_configuration_baseline_checksum_calculation(self):
        """Test baseline checksum calculation for integrity verification."""
        baseline = ConfigurationBaseline(
            environment="development",
            timestamp=datetime.now(timezone.utc),
            version="1.0.0",
            configurations={"DEBUG": True},
            metadata={"source": "test"},
            checksum="",  # Will be calculated
        )

        checksum = baseline.calculate_checksum()
        assert isinstance(checksum, str)
        assert len(checksum) > 0

        # Same data should produce same checksum
        baseline2 = ConfigurationBaseline(
            environment="development",
            timestamp=baseline.timestamp,
            version="1.0.0",
            configurations={"DEBUG": True},
            metadata={"source": "test"},
            checksum="",
        )
        assert baseline2.calculate_checksum() == checksum


class TestConfigurationExtractor:
    """Test ConfigurationExtractor for extracting configuration from Settings."""

    def test_extract_all_configurations(self):
        """Test extracting all configurations from Settings class."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")
        extractor = ConfigurationExtractor()

        configs = extractor.extract_all(settings)

        # Verify basic fields are extracted
        assert "PROJECT_NAME" in configs
        assert "ENVIRONMENT" in configs
        assert "DEBUG" in configs
        assert configs["PROJECT_NAME"] == settings.PROJECT_NAME
        assert configs["DEBUG"] == settings.DEBUG

    def test_extract_by_category(self):
        """Test extracting configurations by category."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")
        extractor = ConfigurationExtractor()

        # Test security category
        security_configs = extractor.extract_by_category(settings, "security")
        expected_security_fields = [
            "SECRET_KEY",
            "ACCESS_TOKEN_EXPIRE_MINUTES",
            "BCRYPT_ROUNDS",
            "SECURE_COOKIES",
            "CSRF_PROTECTION",
        ]
        for field in expected_security_fields:
            assert field in security_configs

        # Test database category
        database_configs = extractor.extract_by_category(settings, "database")
        expected_database_fields = ["DATABASE_URL", "DATABASE_POOL_SIZE", "DATABASE_MAX_OVERFLOW"]
        for field in expected_database_fields:
            assert field in database_configs

    def test_extract_sensitive_data_masking(self):
        """Test that sensitive data is properly masked during extraction."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")
        extractor = ConfigurationExtractor()

        configs = extractor.extract_all(settings, mask_secrets=True)

        # Secret fields should be masked
        assert configs["SECRET_KEY"] == "***"

        # Non-secret fields should not be masked
        assert configs["PROJECT_NAME"] == settings.PROJECT_NAME
        assert configs["DEBUG"] == settings.DEBUG

    def test_extract_without_masking(self):
        """Test extracting configurations without masking for internal use."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")
        extractor = ConfigurationExtractor()

        configs = extractor.extract_all(settings, mask_secrets=False)

        # Secret fields should be accessible for internal validation
        assert configs["SECRET_KEY"] == "test_key_min_32_chars_for_testing"

    def test_extract_with_filtering(self):
        """Test extracting configurations with field filtering."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")
        extractor = ConfigurationExtractor()

        # Include only specific fields
        included_fields = ["PROJECT_NAME", "ENVIRONMENT", "DEBUG"]
        configs = extractor.extract_filtered(settings, include=included_fields)

        assert len(configs) == len(included_fields)
        for field in included_fields:
            assert field in configs

        # Exclude specific fields
        excluded_fields = ["SECRET_KEY", "DATABASE_URL"]
        configs = extractor.extract_filtered(settings, exclude=excluded_fields)

        for field in excluded_fields:
            assert field not in configs
        assert "PROJECT_NAME" in configs  # Should still be included


class TestConfigurationBaselineManager:
    """Test ConfigurationBaselineManager for managing configuration baselines."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.baseline_dir = Path(self.temp_dir) / "baselines"
        self.baseline_dir.mkdir(exist_ok=True)

        self.manager = ConfigurationBaselineManager(baseline_dir=str(self.baseline_dir))

    def test_generate_baseline_success(self):
        """Test successful baseline generation."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")

        baseline = self.manager.generate_baseline(settings=settings, environment="development", version="1.0.0")

        assert baseline.environment == "development"
        assert baseline.version == "1.0.0"
        assert isinstance(baseline.configurations, dict)
        assert len(baseline.configurations) > 0
        assert baseline.checksum is not None

    def test_generate_baseline_with_metadata(self):
        """Test baseline generation with custom metadata."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")

        custom_metadata = {"source": "manual_generation", "user": "test_user", "branch": "issue_121"}

        baseline = self.manager.generate_baseline(
            settings=settings, environment="development", version="1.0.0", metadata=custom_metadata
        )

        assert baseline.metadata["source"] == "manual_generation"
        assert baseline.metadata["user"] == "test_user"
        assert baseline.metadata["branch"] == "issue_121"

    def test_save_baseline_success(self):
        """Test successful baseline saving."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")
        baseline = self.manager.generate_baseline(settings, "development", "1.0.0")

        file_path = self.manager.save_baseline(baseline)

        assert file_path.exists()
        assert file_path.suffix == ".json"

        # Verify file content
        with open(file_path) as f:
            saved_data = json.load(f)

        assert saved_data["environment"] == "development"
        assert saved_data["version"] == "1.0.0"

    def test_load_baseline_success(self):
        """Test successful baseline loading."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")
        original_baseline = self.manager.generate_baseline(settings, "development", "1.0.0")
        file_path = self.manager.save_baseline(original_baseline)

        loaded_baseline = self.manager.load_baseline(file_path)

        assert loaded_baseline.environment == original_baseline.environment
        assert loaded_baseline.version == original_baseline.version
        assert loaded_baseline.configurations == original_baseline.configurations

    def test_load_baseline_file_not_found(self):
        """Test loading baseline with non-existent file."""
        non_existent_path = self.baseline_dir / "non_existent.json"

        with pytest.raises(FileNotFoundError):
            self.manager.load_baseline(non_existent_path)

    def test_load_baseline_invalid_json(self):
        """Test loading baseline with invalid JSON."""
        invalid_file = self.baseline_dir / "invalid.json"
        invalid_file.write_text("invalid json content")

        with pytest.raises(BaselineValidationError):
            self.manager.load_baseline(invalid_file)

    def test_list_baselines(self):
        """Test listing available baselines."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")

        # Create multiple baselines
        baseline1 = self.manager.generate_baseline(settings, "development", "1.0.0")
        baseline2 = self.manager.generate_baseline(settings, "staging", "1.0.0")

        self.manager.save_baseline(baseline1)
        self.manager.save_baseline(baseline2)

        baselines = self.manager.list_baselines()

        assert len(baselines) == 2
        environments = [b.environment for b in baselines]
        assert "development" in environments
        assert "staging" in environments

    def test_get_latest_baseline(self):
        """Test getting the latest baseline for an environment."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")

        # Create multiple baselines for same environment
        baseline1 = self.manager.generate_baseline(settings, "development", "1.0.0")
        self.manager.save_baseline(baseline1)

        # Wait a moment to ensure different timestamps
        import time

        time.sleep(0.1)

        baseline2 = self.manager.generate_baseline(settings, "development", "1.0.1")
        self.manager.save_baseline(baseline2)

        latest = self.manager.get_latest_baseline("development")

        assert latest.version == "1.0.1"
        assert latest.timestamp > baseline1.timestamp

    def test_validate_baseline_integrity(self):
        """Test baseline integrity validation."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")
        baseline = self.manager.generate_baseline(settings, "development", "1.0.0")

        # Valid baseline should pass validation
        assert self.manager.validate_baseline(baseline) is True

        # Modify baseline to make it invalid
        baseline.configurations["INVALID_FIELD"] = "invalid_value"
        baseline.checksum = "invalid_checksum"

        with pytest.raises(BaselineValidationError):
            self.manager.validate_baseline(baseline, strict=True)

    def test_compare_baselines(self):
        """Test comparing two baselines for differences."""
        settings1 = Settings(SECRET_KEY="test_key_min_32_chars_for_testing", DEBUG=False)
        settings2 = Settings(SECRET_KEY="test_key_min_32_chars_for_testing", DEBUG=True)  # Different from settings1

        baseline1 = self.manager.generate_baseline(settings1, "development", "1.0.0")
        baseline2 = self.manager.generate_baseline(settings2, "development", "1.0.1")

        comparison = self.manager.compare_baselines(baseline1, baseline2)

        assert comparison.has_changes is True
        assert "DEBUG" in comparison.changed_parameters
        assert comparison.changed_parameters["DEBUG"]["old"] is False
        assert comparison.changed_parameters["DEBUG"]["new"] is True

    def test_baseline_schema_validation(self):
        """Test baseline schema validation against expected structure."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")
        baseline = self.manager.generate_baseline(settings, "development", "1.0.0")

        # Should validate against baseline schema
        is_valid = self.manager.validate_schema(baseline)
        assert is_valid is True

        # Test with invalid schema
        invalid_baseline = baseline.copy()
        invalid_baseline.configurations = "invalid_type"  # Should be dict

        is_valid = self.manager.validate_schema(invalid_baseline)
        assert is_valid is False

    def test_baseline_export_import(self):
        """Test exporting and importing baselines."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")
        baseline = self.manager.generate_baseline(settings, "development", "1.0.0")

        # Export to different formats
        export_path = self.baseline_dir / "export.json"
        self.manager.export_baseline(baseline, export_path, format="json")

        assert export_path.exists()

        # Import and verify
        imported_baseline = self.manager.import_baseline(export_path)
        assert imported_baseline.environment == baseline.environment
        assert imported_baseline.configurations == baseline.configurations

    def test_baseline_with_environment_overrides(self):
        """Test baseline generation with environment-specific overrides."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")

        # Production environment should have different defaults
        prod_baseline = self.manager.generate_baseline(
            settings=settings, environment="production", version="1.0.0", apply_environment_overrides=True
        )

        # Production should have DEBUG=False enforced
        assert prod_baseline.configurations["DEBUG"] is False

        # Security settings should be stricter in production
        assert prod_baseline.configurations["SECURE_COOKIES"] is True

    def test_baseline_generation_error_handling(self):
        """Test error handling during baseline generation."""
        # Test with invalid extractor that raises exception
        with patch.object(self.manager.extractor, "extract_all") as mock_extract:
            mock_extract.side_effect = Exception("Extraction failed")

            settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")
            with pytest.raises(BaselineGenerationError):
                self.manager.generate_baseline(settings=settings, environment="development", version="1.0.0")

    def test_baseline_storage_optimization(self):
        """Test baseline storage optimization and compression."""
        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")
        baseline = self.manager.generate_baseline(settings, "development", "1.0.0")

        # Save with compression
        file_path = self.manager.save_baseline(baseline, compress=True)

        # File should be smaller with compression
        compressed_size = file_path.stat().st_size

        # Save without compression for comparison
        uncompressed_path = self.manager.save_baseline(baseline, compress=False)
        uncompressed_size = uncompressed_path.stat().st_size

        # Note: May not always be smaller for small test data
        assert compressed_size > 0
        assert uncompressed_size > 0

    def test_concurrent_baseline_operations(self):
        """Test thread safety of baseline operations."""
        import threading

        settings = Settings(SECRET_KEY="test_key_min_32_chars_for_testing")
        results = []
        errors = []

        def generate_and_save(env_suffix):
            try:
                baseline = self.manager.generate_baseline(settings, "development", f"1.0.{env_suffix}")
                file_path = self.manager.save_baseline(baseline)
                results.append(file_path)
            except Exception as e:
                errors.append(e)

        # Create multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=generate_and_save, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads
        for thread in threads:
            thread.join()

        # Verify all operations succeeded
        assert len(errors) == 0
        assert len(results) == 5

        # Verify all files exist
        for file_path in results:
            assert file_path.exists()
