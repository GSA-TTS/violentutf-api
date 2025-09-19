"""Configuration Baseline Manager.

This module provides functionality for creating, managing, and validating
configuration baselines for the ViolentUTF API system.
"""

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator

from app.core.config import Settings


class BaselineGenerationError(Exception):
    """Exception raised when baseline generation fails."""

    pass


class BaselineValidationError(Exception):
    """Exception raised when baseline validation fails."""

    pass


class ConfigurationBaseline(BaseModel):
    """Configuration baseline data model."""

    environment: str = Field(..., pattern="^(development|staging|production)$")
    timestamp: datetime
    version: str = Field(..., min_length=1)
    configurations: Dict[str, Any]
    metadata: Dict[str, Any] = Field(default_factory=dict)
    checksum: str = Field(default="")

    class Config:
        """Pydantic configuration."""

        json_encoders = {datetime: lambda v: v.isoformat()}

    def calculate_checksum(self) -> str:
        """Calculate checksum for baseline integrity verification."""
        # Create deterministic string representation
        data_for_hash = {
            "environment": self.environment,
            "version": self.version,
            "configurations": self.configurations,
            "metadata": self.metadata,
        }

        # Sort keys to ensure consistent ordering
        json_str = json.dumps(data_for_hash, sort_keys=True, default=str)
        return hashlib.sha256(json_str.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert baseline to dictionary."""
        return {
            "environment": self.environment,
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
            "configurations": self.configurations,
            "metadata": self.metadata,
            "checksum": self.checksum,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConfigurationBaseline":
        """Create baseline from dictionary."""
        if isinstance(data["timestamp"], str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
        return cls(**data)


class ConfigurationExtractor:
    """Extracts configuration from Settings class."""

    SECURITY_FIELDS = {
        "SECRET_KEY",
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        "BCRYPT_ROUNDS",
        "SECURE_COOKIES",
        "CSRF_PROTECTION",
        "JWT_SECRET_KEY",
        "VAULT_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
    }

    DATABASE_FIELDS = {
        "DATABASE_URL",
        "DATABASE_POOL_SIZE",
        "DATABASE_MAX_OVERFLOW",
        "REPOSITORY_CONNECTION_TIMEOUT",
        "REPOSITORY_QUERY_TIMEOUT",
    }

    def extract_all(self, settings: Settings, mask_secrets: bool = True) -> Dict[str, Any]:
        """Extract all configuration from Settings."""
        try:
            return settings.to_dict(mask_secrets=mask_secrets)
        except Exception as e:
            raise BaselineGenerationError(f"Failed to extract configurations: {e}")

    def extract_by_category(self, settings: Settings, category: str) -> Dict[str, Any]:
        """Extract configuration by category."""
        all_configs = self.extract_all(settings, mask_secrets=True)

        if category == "security":
            return {k: v for k, v in all_configs.items() if k in self.SECURITY_FIELDS}
        elif category == "database":
            return {k: v for k, v in all_configs.items() if k in self.DATABASE_FIELDS}
        else:
            return all_configs

    def extract_filtered(
        self, settings: Settings, include: Optional[List[str]] = None, exclude: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Extract configuration with filtering."""
        all_configs = self.extract_all(settings)

        if include:
            return {k: v for k, v in all_configs.items() if k in include}

        if exclude:
            return {k: v for k, v in all_configs.items() if k not in exclude}

        return all_configs


class BaselineComparison:
    """Represents comparison between two baselines."""

    def __init__(self) -> None:
        self.has_changes: bool = False
        self.changed_parameters: Dict[str, Dict[str, Any]] = {}
        self.added_parameters: Dict[str, Any] = {}
        self.removed_parameters: Dict[str, Any] = {}

    def add_change(self, parameter: str, old_value: Any, new_value: Any) -> None:
        """Add a parameter change."""
        self.has_changes = True
        self.changed_parameters[parameter] = {"old": old_value, "new": new_value}


class ConfigurationBaselineManager:
    """Manages configuration baselines."""

    def __init__(self, baseline_dir: str = "./baselines"):
        """Initialize baseline manager."""
        self.baseline_dir = Path(baseline_dir)
        self.baseline_dir.mkdir(exist_ok=True)
        self.extractor = ConfigurationExtractor()

    def generate_baseline(
        self,
        settings: Settings,
        environment: str,
        version: str,
        metadata: Optional[Dict[str, Any]] = None,
        apply_environment_overrides: bool = False,
    ) -> ConfigurationBaseline:
        """Generate configuration baseline from Settings."""
        try:
            # Extract configurations
            configurations = self.extractor.extract_all(settings, mask_secrets=True)

            # Apply environment-specific overrides
            if apply_environment_overrides and environment == "production":
                configurations["DEBUG"] = False
                configurations["SECURE_COOKIES"] = True

            # Prepare metadata
            baseline_metadata = {
                "source": "settings_class",
                "generator": "config_baseline_manager",
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
            if metadata:
                baseline_metadata.update(metadata)

            # Create baseline
            baseline = ConfigurationBaseline(
                environment=environment,
                timestamp=datetime.now(timezone.utc),
                version=version,
                configurations=configurations,
                metadata=baseline_metadata,
                checksum="",
            )

            # Calculate and set checksum
            baseline.checksum = baseline.calculate_checksum()

            return baseline

        except Exception as e:
            raise BaselineGenerationError(f"Failed to generate baseline: {e}")

    def save_baseline(self, baseline: ConfigurationBaseline, compress: bool = False) -> Path:
        """Save baseline to file."""
        timestamp_str = baseline.timestamp.strftime("%Y%m%d_%H%M%S")
        filename = f"{baseline.environment}_{baseline.version}_{timestamp_str}.json"
        file_path = self.baseline_dir / filename

        try:
            with open(file_path, "w") as f:
                json.dump(baseline.to_dict(), f, indent=2, default=str)

            return file_path

        except Exception as e:
            raise BaselineGenerationError(f"Failed to save baseline: {e}")

    def load_baseline(self, file_path: Path) -> ConfigurationBaseline:
        """Load baseline from file."""
        if not file_path.exists():
            raise FileNotFoundError(f"Baseline file not found: {file_path}")

        try:
            with open(file_path) as f:
                data = json.load(f)

            return ConfigurationBaseline.from_dict(data)

        except json.JSONDecodeError as e:
            raise BaselineValidationError(f"Invalid JSON in baseline file: {e}")
        except Exception as e:
            raise BaselineValidationError(f"Failed to load baseline: {e}")

    def list_baselines(self) -> List[ConfigurationBaseline]:
        """List all available baselines."""
        baselines = []

        for file_path in self.baseline_dir.glob("*.json"):
            try:
                baseline = self.load_baseline(file_path)
                baselines.append(baseline)
            except Exception:
                # Skip invalid baseline files
                continue

        # Sort by timestamp (newest first)
        return sorted(baselines, key=lambda b: b.timestamp, reverse=True)

    def get_latest_baseline(self, environment: str) -> Optional[ConfigurationBaseline]:
        """Get the latest baseline for an environment."""
        baselines = [b for b in self.list_baselines() if b.environment == environment]
        return baselines[0] if baselines else None

    def validate_baseline(self, baseline: ConfigurationBaseline, strict: bool = False) -> bool:
        """Validate baseline integrity."""
        try:
            # Check checksum
            expected_checksum = baseline.calculate_checksum()
            if baseline.checksum != expected_checksum:
                if strict:
                    raise BaselineValidationError("Baseline checksum mismatch")
                return False

            # Validate required fields
            if not baseline.environment or not baseline.version:
                if strict:
                    raise BaselineValidationError("Missing required fields")
                return False

            return True

        except Exception as e:
            if strict:
                raise BaselineValidationError(f"Baseline validation failed: {e}")
            return False

    def compare_baselines(
        self, baseline1: ConfigurationBaseline, baseline2: ConfigurationBaseline
    ) -> BaselineComparison:
        """Compare two baselines for differences."""
        comparison = BaselineComparison()

        config1 = baseline1.configurations
        config2 = baseline2.configurations

        # Find all unique keys
        all_keys = set(config1.keys()) | set(config2.keys())

        for key in all_keys:
            value1 = config1.get(key)
            value2 = config2.get(key)

            if value1 != value2:
                comparison.add_change(key, value1, value2)

        return comparison

    def validate_schema(self, baseline: ConfigurationBaseline) -> bool:
        """Validate baseline against expected schema."""
        try:
            # Validate environment
            if baseline.environment not in ["development", "staging", "production"]:
                return False

            # Validate version format
            if not baseline.version or len(baseline.version) == 0:
                return False

            return True

        except Exception:
            return False

    def export_baseline(self, baseline: ConfigurationBaseline, export_path: Path, format: str = "json") -> None:
        """Export baseline to different formats."""
        if format == "json":
            with open(export_path, "w") as f:
                json.dump(baseline.to_dict(), f, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def import_baseline(self, import_path: Path) -> ConfigurationBaseline:
        """Import baseline from file."""
        return self.load_baseline(import_path)
