#!/usr/bin/env python3
"""
Configuration settings for pre-audit tools.

This module provides centralized configuration for all pre-audit tools
to ensure consistent paths and settings.
"""

import os
from pathlib import Path

# Base directories
PROJECT_ROOT = Path.cwd()
DOCS_DIR = PROJECT_ROOT / "docs"
REPORTS_DIR = DOCS_DIR / "reports" / "ADRaudit-claudecode"

# Ensure reports directory exists
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Default configuration
DEFAULT_CONFIG = {
    "reports": {
        "output_dir": str(REPORTS_DIR),
        "json_enabled": True,
        "html_enabled": True,
        "sarif_enabled": True,
        "github_comment_enabled": True,
    },
    "cache": {
        "base_dir": ".cache/architectural_analysis",
        "memory_size_mb": 100,
        "disk_size_mb": 1024,
        "ttl_hours": 72,
    },
    "smart_triggers": {
        "config_file": ".architectural-triggers.yml",
        "rate_limit_daily": 10,
        "rate_limit_per_developer": 3,
    },
    "pattern_analysis": {
        "config_file": "config/ci_violation_patterns.yml",
        "parallel_workers": 4,
        "confidence_threshold": 0.7,
    },
}

# Environment variable overrides
REPORTS_OUTPUT_DIR = os.getenv("REPORTS_OUTPUT_DIR", DEFAULT_CONFIG["reports"]["output_dir"])
CACHE_BASE_DIR = os.getenv("CACHE_BASE_DIR", DEFAULT_CONFIG["cache"]["base_dir"])
